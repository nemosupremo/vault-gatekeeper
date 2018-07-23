package gatekeeper

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/franela/goreq"
	gkClient "github.com/nemosupremo/vault-gatekeeper/gatekeeper"
	"github.com/nemosupremo/vault-gatekeeper/policy"
	"github.com/nemosupremo/vault-gatekeeper/scheduler"
	"github.com/nemosupremo/vault-gatekeeper/usagestore"
	"github.com/nemosupremo/vault-gatekeeper/vault"
	"github.com/nemosupremo/vault-gatekeeper/vault/unsealer"
	"github.com/segmentio/ksuid"
	log "github.com/sirupsen/logrus"
)

var ErrSealed = errors.New("Gatekeeper is sealed.")
var ErrTaskNotFresh = errors.New("This task has been running too long to request a token.")
var ErrMaxTokensGiven = errors.New("Maximum number of tokens given to this task.")
var ErrNoPolicy = errors.New("Your task doesn't match any configured policy.")
var ErrRoleMismatch = errors.New("Your task does not have permission to use this role.")
var ErrNoSuchRole = errors.New("The role requested does not exist.")
var ErrNoPolicyConfigured = errors.New("No policies have been configured.")
var ErrHostMismatch = errors.New("The service's remote address requesting this token does not match the host of the service running this task.")

type Config struct {
	ListenAddress    string
	TlsCert          string
	TlsKey           string
	DefaultScheduler string
	Schedulers       []string
	Store            string
	StoreVaultPath   string
	Peers            string
	HostCheck        bool
	UseImageNames    bool

	Vault struct {
		Address      string
		CaCert       string
		CaPath       string
		ClientCert   string
		ClientKey    string
		Insecure     bool
		KvVersion    string
		AppRoleMount string
	}

	Metrics struct {
		Ticker time.Duration
		Statsd struct {
			Host    string
			Prefix  string
			Influx  bool
			Datadog bool
		}
	}

	PolicyPath  string
	MaxTaskLife time.Duration

	Unsealer unsealer.Unsealer

	Version string

	SkipPolicyLoading bool
}

type peer struct {
	Protocol string `json:"-"`
	Host     string `json:"-"`
	Id       string `json:"id"`
	Address  string `json:"address"`
	Unsealed bool   `json:"unsealed"`
	Version  string `json:"version"`
}

func (p peer) address() string {
	var u url.URL
	u.Scheme = p.Protocol
	u.Host = p.Host
	u.Path = "/"
	return u.String()
}

func (p peer) TokenUri() string {
	var u url.URL
	u.Scheme = p.Protocol
	u.Host = p.Host
	u.Path = "/token"
	return u.String()
}

func (p peer) ReloadUri() string {
	var u url.URL
	u.Scheme = p.Protocol
	u.Host = p.Host
	u.Path = "/policies/reload"
	return u.String()
}

func (p peer) String() string {
	var u url.URL
	u.Scheme = p.Protocol
	u.Host = p.Host
	s := "sealed"
	if p.Unsealed {
		s = "unsealed"
	}
	u.User = url.UserPassword(p.Id, s)
	return u.String()
}

type Gatekeeper struct {
	config Config

	Store      usagestore.UsageStore
	Schedulers map[string]scheduler.Scheduler
	Policies   *policy.Policies `json:"-"`
	Stats      struct {
		Requests   int32 `json:"requests"`
		Successful int32 `json:"successful"`
		Denied     int32 `json:"denied"`
		Failed     int32 `json:"failed"`
	} `json:"stats"`
	Started time.Time `json:"started"`
	Token   string    `json:"-"`
	metrics *metrics
	PeerId  string `json:"peer_id"`
	peers   atomic.Value
	renewer struct {
		control chan struct{}
		wg      sync.WaitGroup
	}

	sync.RWMutex
}

func NewGatekeeper(conf Config) (*Gatekeeper, error) {
	g := &Gatekeeper{
		config:     conf,
		Started:    time.Now(),
		Schedulers: make(map[string]scheduler.Scheduler),
		PeerId:     ksuid.New().String(),
	}

	if g.config.Vault.Insecure ||
		g.config.Vault.CaCert != "" ||
		g.config.Vault.CaPath != "" ||
		g.config.Vault.ClientCert != "" ||
		g.config.Vault.ClientKey != "" {
		tr := &http.Transport{
			Dial:            goreq.DefaultDialer.Dial,
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{},
		}
		if g.config.Vault.Insecure {
			tr.TLSClientConfig.InsecureSkipVerify = true
		}

		if g.config.Vault.CaPath != "" || g.config.Vault.CaCert != "" {
			LoadCA := func() (*x509.CertPool, error) {
				if g.config.Vault.CaCert != "" {
					return gkClient.LoadCACert(g.config.Vault.CaCert)
				} else if g.config.Vault.CaPath != "" {
					return gkClient.LoadCAPath(g.config.Vault.CaPath)
				}
				panic("invariant violation")
			}
			if certs, err := LoadCA(); err == nil {
				tr.TLSClientConfig.RootCAs = certs
			} else {
				return nil, errors.New("Failed to read server root certs: " + err.Error())
			}
		}

		if g.config.Vault.ClientCert != "" || g.config.Vault.ClientKey != "" {
			if cert, err := tls.LoadX509KeyPair(g.config.Vault.ClientCert, g.config.Vault.ClientKey); err == nil {
				tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
				tr.TLSClientConfig.BuildNameToCertificate()
			} else {
				return nil, errors.New("Failed to read client certs: " + err.Error())
			}
		}

		goreq.DefaultTransport = tr
		goreq.DefaultClient = &http.Client{Transport: goreq.DefaultTransport}
	}

	if len(g.config.PolicyPath) == 0 {
		return nil, errors.New("Invalid policy path.")
	}

	if len(conf.Schedulers) == 0 {
		return nil, errors.New("No schedulers were provided.")
	}

	for _, sched := range conf.Schedulers {
		if sched == "_null_cmd" {
			continue
		}
		if f, ok := scheduler.Get(sched); ok {
			if s, err := f(); err == nil {
				g.Schedulers[sched] = s
			} else {
				return nil, errors.New("Failed to instatiate scheduler '" + sched + "': " + err.Error())
			}
		} else {
			return nil, errors.New("Could not instatiate '" + sched + "'. This scheduler is not registered.")
		}
	}

	switch conf.Store {
	case "memory":
		var err error
		if g.Store, err = usagestore.NewInMemoryUsageStore(); err != nil {
			return nil, err
		}
	case "vault":
		var err error
		if g.Store, err = usagestore.NewVaultStore(g.config.StoreVaultPath); err != nil {
			return nil, err
		}
	case "_null_cmd":

	default:
		return nil, errors.New("Could not instatiate '" + conf.Store + "'. This store is not recognized.")
	}

	if len(conf.Peers) > 0 {
		if conf.Store == "memory" {
			return nil, errors.New("The peers option was set, but the usage-store type is memory. The memory store does not support high availability.")
		}
	}

	if metrics, err := g.NewMetrics(conf); err == nil {
		g.metrics = metrics
	} else {
		return nil, err
	}

	if len(g.config.Peers) > 0 {
		if peers, err := g.LoadPeers(g.PeerId, true); err == nil {
			g.peers.Store(peers)
		} else {
			return nil, err
		}
	} else {
		g.peers.Store([]peer{})
	}

	if conf.Unsealer != nil {
		if err := g.Unseal(conf.Unsealer); err == ErrNoPolicyConfigured {
			return nil, err
		}
	}

	return g, nil
}

func (g *Gatekeeper) Unseal(u unsealer.Unsealer) error {
	log.Infof("Attempting to unseal with '%s' method.", u.Name())
	g.Lock()

	if token, err := u.Token(); err == nil {
		log.Infof("Successfully unsealed with '%s' method.", u.Name())
		g.Token = token
		if g.config.SkipPolicyLoading {
			g.Unlock()
			return nil
		}
		if policies, err := g.loadPolicies(); err == nil {
			log.Infof("Loaded policies. %d total policies.", policies.Len())
			g.Policies = policies
			if g.renewer.control != nil {
				close(g.renewer.control)
				g.renewer.control = nil
			}
			g.renewer.wg.Wait()
			g.renewer.wg.Add(1)
			g.renewer.control = make(chan struct{})
			go g.RenewalWorker(g.renewer.control)
			g.Unlock()
			return nil
		} else {
			g.Token = ""
			log.Warnf("Failed to load policies! Gatekeeper will remain sealed as no policies were loaded. Error: %v", err)
			g.Unlock()
			return ErrNoPolicyConfigured
		}
	} else {
		g.Unlock()
		log.Warnf("Failed to unseal gatekeeper: %v", err.Error())
		return err
	}
}

func (g *Gatekeeper) Seal() error {
	g.Lock()
	defer g.Unlock()
	g.Token = ""
	if g.renewer.control != nil {
		close(g.renewer.control)
		g.renewer.control = nil
	}
	log.Infof("Gatekeeper sealed.")
	return nil
}

func (g *Gatekeeper) IsUnsealed() bool {
	g.RLock()
	r := g.Token != ""
	g.RUnlock()
	return r
}

func (g *Gatekeeper) Serve() error {
	go g.watchPeers()
	r := g.Routes()
	if g.config.TlsCert != "" || g.config.TlsKey != "" {
		return ListenAndServeTLS(g.config.ListenAddress, g.config.TlsCert, g.config.TlsKey, r)
	}
	return http.ListenAndServe(g.config.ListenAddress, r)
}

func (g *Gatekeeper) GetRoleId(roleName string, authToken string) (string, error) {
	r, err := vault.Request{goreq.Request{
		Uri:             vault.Path(path.Join("v1/auth", g.config.Vault.AppRoleMount, "role", roleName, "role-id")),
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", authToken)}.Do()
	if err == nil {
		switch r.StatusCode {
		case 200:
			var resp struct {
				Data struct {
					RoleId string `json:"role_id"`
				} `json:"data"`
			}
			if err := r.Body.FromJsonTo(&resp); err == nil {
				return resp.Data.RoleId, nil
			} else {
				return "", err
			}
		case 404:
			return "", ErrNoSuchRole
		default:
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return "", e
			} else {
				e.Errors = []string{"communication error."}
				return "", e
			}
		}
	} else {
		return "", err
	}
}

func (g *Gatekeeper) GetSecretId(roleName string, authToken string) (string, error) {
	r, err := vault.Request{goreq.Request{
		Uri:             vault.Path(path.Join("v1/auth", g.config.Vault.AppRoleMount, "role", roleName, "secret-id")),
		MaxRedirects:    10,
		RedirectHeaders: true,
		Method:          "POST",
	}.WithHeader("X-Vault-Token", authToken)}.Do()
	if err == nil {
		switch r.StatusCode {
		case 200:
			var resp struct {
				Data struct {
					SecretId string `json:"secret_id"`
				} `json:"data"`
			}
			if err := r.Body.FromJsonTo(&resp); err == nil {
				return resp.Data.SecretId, nil
			} else {
				return "", err
			}
		default:
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return "", e
			} else {
				e.Errors = []string{"communication error."}
				return "", e
			}
		}
	} else {
		return "", err
	}
}

func (g *Gatekeeper) RequestToken(providerKey string, taskId string, requestedRole string, remoteAddr string) (string, time.Duration, error) {
	g.metrics.Request()
	if !g.IsUnsealed() {
		g.metrics.Denied()
		return "", 0, ErrSealed
	}
	if providerKey == "" {
		providerKey = g.config.DefaultScheduler
	}
	var remoteAddrs []net.IP
	if remoteAddr != "" {
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
			remoteAddr = host
		}
		if ip, err := net.LookupIP(remoteAddr); err == nil {
			remoteAddrs = ip
		}
	}
	if provider, ok := g.Schedulers[providerKey]; ok {
		if task, err := provider.LookupTask(taskId); err == nil {
			if time.Since(task.StartTime()) >= g.config.MaxTaskLife {
				g.metrics.Denied()
				return "", 0, ErrTaskNotFresh
			}
			if g.config.HostCheck {
				pass := false
				for _, remoteAddr := range remoteAddrs {
					if remoteAddr.Equal(task.IP()) {
						pass = true
						break
					}
				}
				if !pass {
					return "", 0, ErrHostMismatch
				}
			}

			taskName := task.Name()
			if g.config.UseImageNames && task.Image() != "" {
				taskName = task.Image()
			}

			policyKey := providerKey + ":" + taskName
			if task.Group() != "" && !g.config.UseImageNames {
				policyKey = providerKey + ":" + task.Group() + ":" + taskName
			}
			g.RLock()
			currentPolicies := g.Policies
			g.RUnlock()

			if policy, ok := currentPolicies.Get(policyKey); ok && len(policy.Roles) > 0 {
				if err := g.Store.Acquire(g.Token, providerKey+":"+task.Id(), policy.NumUses, g.config.MaxTaskLife+1*time.Minute); err == nil {
					roleName := policy.Roles[0]
					if requestedRole != "" {
						allowed := false
						for _, role := range policy.Roles {
							if requestedRole == role {
								allowed = true
								break
							}
						}
						if !allowed {
							g.metrics.Denied()
							return "", 0, ErrRoleMismatch
						}
					}
					if roleName == "{{name}}" {
						roleName = task.Name()
					}

					g.RLock()
					authToken := g.Token
					g.RUnlock()

					if roleId, err := g.GetRoleId(roleName, authToken); err == nil {
						if secretId, err := g.GetSecretId(roleName, authToken); err == nil {
							uns := unsealer.AppRoleUnsealer{
								RoleId:   roleId,
								SecretId: secretId,
								Endpoint: g.config.Vault.AppRoleMount,
								Wrap:     100 * time.Minute,
							}
							if token, err := uns.Token(); err == nil {
								g.metrics.Success()
								return token, uns.Wrap, nil
							} else {
								g.metrics.Denied()
								return "", 0, err
							}
						} else {
							log.Warnf("recieved error when trying to get the secret id for role %s: %v", roleName, err)
							g.metrics.Failed()
							return "", 0, err
						}
					} else if err == ErrNoSuchRole {
						g.metrics.Denied()
						return "", 0, ErrNoSuchRole
					} else {
						g.metrics.Failed()
						log.Warnf("recieved error when trying to get the role id for role %s: %v", roleName, err)
						return "", 0, err
					}
				} else if err == usagestore.ErrPutLimitExceeded {
					g.metrics.Denied()
					return "", 0, ErrMaxTokensGiven
				} else {
					g.metrics.Denied()
					return "", 0, err
				}
			} else {
				g.metrics.Denied()
				return "", 0, ErrNoPolicy
			}
		} else if err == scheduler.ErrTaskNotFound {
			g.metrics.Denied()
			return "", 0, err
		} else {
			g.metrics.Denied()
			return "", 0, err
		}
	} else {
		return "", 0, errors.New("Provided scheduler '" + providerKey + "' is not configured.")
	}
}

func (g *Gatekeeper) RenewalWorker(controlChan chan struct{}) {
	defer g.renewer.wg.Done()
	timer := time.NewTimer(1 * time.Hour)
	readTimer := false
	for {
		if ttl, err := g.TokenTtl(); err == nil {
			if ttl == 0 {
				// root token
				return
			}
			waitTime := ttl - (10 * time.Second)
			if waitTime < 0 {
				waitTime = 0
			}
			if !timer.Stop() && !readTimer {
				<-timer.C
			}
			readTimer = false
			timer.Reset(waitTime)
			select {
			case <-timer.C:
				readTimer = true
			case <-controlChan:
				return
			}
			if err := g.RenewToken(); err == nil {
				log.Infof("Renewed Vault Token (original ttl: %v)", ttl)
			} else {
				log.Warn("Failed to renew Vault token. Is the policy set correctly? Gatekeeper will now be sealed: %v", err)
				g.Seal()
				return
			}
		} else {
			log.Warnf("Looking up our token's ttl caused an error: %v. Is the policy set correctly? Gatekeeper will now be sealed.", err)
			g.Seal()
			return
		}
	}
}

func (g *Gatekeeper) TokenTtl() (time.Duration, error) {
	if !g.IsUnsealed() {
		return 0, ErrSealed
	}
	g.RLock()
	token := g.Token
	g.RUnlock()
	r, err := vault.Request{goreq.Request{
		Uri:             vault.Path("v1/auth/token/lookup-self"),
		MaxRedirects:    10,
		RedirectHeaders: true,
		Method:          "GET",
	}.WithHeader("X-Vault-Token", token)}.Do()
	if err == nil {
		switch r.StatusCode {
		case 200:
			var resp struct {
				Data struct {
					Ttl int `json:"ttl"`
				} `json:"data"`
			}
			if err := r.Body.FromJsonTo(&resp); err == nil {
				return time.Duration(resp.Data.Ttl) * time.Second, nil
			} else {
				return 0, err
			}
		default:
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return 0, e
			} else {
				e.Errors = []string{"communication error."}
				return 0, e
			}
		}
	} else {
		return 0, err
	}
}

func (g *Gatekeeper) RenewToken() error {
	if !g.IsUnsealed() {
		return ErrSealed
	}
	g.RLock()
	token := g.Token
	g.RUnlock()
	r, err := vault.Request{goreq.Request{
		Uri:             vault.Path("v1/auth/token/renew-self"),
		MaxRedirects:    10,
		RedirectHeaders: true,
		Method:          "POST",
	}.WithHeader("X-Vault-Token", token)}.Do()
	if err == nil {
		switch r.StatusCode {
		case 200, 204:
			return nil
		default:
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return e
			} else {
				e.Errors = []string{"communication error."}
				return e
			}
		}
	} else {
		return err
	}
}

func (g *Gatekeeper) Peers() []peer {
	return g.peers.Load().([]peer)
}

func (g *Gatekeeper) watchPeers() {
	ticker := time.NewTicker(30 * time.Second)
	for {
		<-ticker.C
		if peers, err := g.LoadPeers(g.PeerId, false); err == nil {
			g.peers.Store(peers)
		}
	}
}

func (g *Gatekeeper) LoadPeers(myId string, startup bool) ([]peer, error) {
	protocol := "https"
	var peerHosts []string
	if path, err := url.Parse(g.config.Peers); err == nil {
		switch path.Scheme {
		case "http":
			protocol = "http"
			fallthrough
		case "https":
			peerHosts = strings.Split(path.Host, ",")
		default:
			return nil, errors.New("Invalid option for peers: invalid protocol " + path.Scheme)
		}
	} else {
		peerHosts = strings.Split(g.config.Peers, ",")
	}

	peers := make(map[string]peer)

	for _, peerHost := range peerHosts {
		if host, port, err := net.SplitHostPort(peerHost); err == nil {
			if addrs, err := net.LookupIP(host); err == nil {
				for _, addr := range addrs {
					var u url.URL
					u.Scheme = protocol
					u.Host = net.JoinHostPort(addr.String(), port)
					u.Path = "/status"
					req, err := goreq.Request{
						Uri: u.String(),
					}.WithHeader("Peer-Checker", "true").WithHeader("User-Agent", "Gatekeeper Peer "+g.config.Version).Do()
					if err == nil {
						defer req.Body.Close()
						var status struct {
							Id       string `json:"id"`
							Unsealed bool   `json:"unsealed"`
							Version  string `json:"version"`
						}
						if err := req.Body.FromJsonTo(&status); err == nil {
							if status.Id == myId {
								continue
							}
							if _, ok := peers[status.Id]; ok {
								continue
							}
							peers[status.Id] = peer{
								Protocol: protocol,
								Host:     u.Host,
								Id:       status.Id,
								Unsealed: status.Unsealed,
								Version:  status.Version,
							}
						} else {
							log.Warnf("Failed to parse peer at %v: %v", u.Host, err)
						}
					} else {
						if startup {
							log.Warnf("Failed to load peer at %v: %v. If this is the local peer, then this message should be ignored as the server hasn't started listening yet.", u.Host, err)
						} else {
							log.Infof("Failed to load peer at %v: %v", u.Host, err)
						}
					}
				}
			} else {
				if startup {
					log.Warnf("Failed to lookup host peer %v: %v", peerHost, err)
				} else {
					log.Infof("Failed to lookup host peer %v: %v", peerHost, err)
				}
			}
		} else {
			return nil, err
		}
	}

	p := make([]peer, len(peers))
	i := 0
	for _, v := range peers {
		p[i] = v
		i++
	}
	return p, nil
}
