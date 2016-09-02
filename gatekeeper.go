package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/channelmeter/vault-gatekeeper-mesos/gatekeeper"
	"github.com/franela/goreq"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

type GkStatus string

const (
	StatusSealed   GkStatus = "Sealed"
	StatusUnsealed GkStatus = "Unsealed"
)

var gitNearestTag = "dev"

var config struct {
	Vault struct {
		Server     string
		Insecure   bool
		CaCert     string
		CaPath     string
		GkPolicies string
	}
	SelfRecreate     bool
	ListenAddress    string
	TlsCert          string
	TlsKey           string
	Mesos            string
	MaxTaskLife      time.Duration
	AppIdAuth        AppIdUnsealer
	CubbyAuth        CubbyUnsealer
	WrappedTokenAuth WrappedTokenUnsealer
}

var state struct {
	Status GkStatus `json:"status"`
	Stats  struct {
		Requests   int32 `json:"requests"`
		Successful int32 `json:"successful"`
		Denied     int32 `json:"denied"`
	} `json:"stats"`
	Started  time.Time     `json:"started"`
	Token    string        `json:"-"`
	OnSealed chan struct{} `json:"-"`
	sync.RWMutex

	// TODO: Remove this when we can incorporate Mesos in testing environment
	testingTaskId string
}

var errAlreadyUnsealed = errors.New("Already unsealed.")
var errUnknownAuthMethod = errors.New("Unknown method for authorization.")

func defaultEnvVar(key string, def string) (val string) {
	val = os.Getenv(key)
	if val == "" {
		val = def
	}
	return
}

func init() {
	flag.StringVar(&config.ListenAddress, "listen", defaultEnvVar("LISTEN_ADDR", ":9201"), "Hostname and port to listen on. (Overrides the LISTEN_ADDR environment variable if set.)")
	flag.StringVar(&config.TlsCert, "tls-cert", defaultEnvVar("TLS_CERT", ""), "Path to TLS certificate. If this value is set, gatekeeper will be served over TLS.")
	flag.StringVar(&config.TlsKey, "tls-key", defaultEnvVar("TLS_KEY", ""), "Path to TLS key. If this value is set, gatekeeper will be served over TLS.")

	flag.StringVar(&config.Mesos, "mesos", defaultEnvVar("MESOS_MASTER", ""), "Address to mesos master. (Overrides the MESOS_MASTER environment variable if set.)")

	flag.StringVar(&config.Vault.Server, "vault", defaultEnvVar("VAULT_ADDR", ""), "Address to vault server. (Overrides the VAULT_ADDR environment variable if set.)")
	flag.StringVar(&config.Vault.GkPolicies, "policies", defaultEnvVar("GATE_POLICIES", "/gatekeeper"), "Path to the json formatted policies configuration file on the vault generic backend.")
	flag.BoolVar(&config.Vault.Insecure, "tls-skip-verify", func() bool {
		b, err := strconv.ParseBool(defaultEnvVar("VAULT_SKIP_VERIFY", "0"))
		return err == nil && b
	}(), "Do not verify TLS certificate. (Overrides the VAULT_SKIP_VERIFY environment variable if set.)")
	flag.StringVar(&config.Vault.CaCert, "ca-cert", defaultEnvVar("VAULT_CACERT", ""), "Path to a PEM encoded CA cert file to use to verify the Vault server SSL certificate. (Overrides the VAULT_CACERT environment variable if set.)")
	flag.StringVar(&config.Vault.CaPath, "ca-path", defaultEnvVar("VAULT_CAPATH", ""), "Path to a directory of PEM encoded CA cert files to verify the Vault server SSL certificate. (Overrides the VAULT_CAPATH environment variable if set.)")

	flag.StringVar(&config.CubbyAuth.TempToken, "cubby-token", defaultEnvVar("CUBBY_TOKEN", ""), "Temporary vault authorization token that has a cubbyhole secret in CUBBY_PATH that contains the permanent vault token.")
	flag.StringVar(&config.CubbyAuth.Path, "cubby-path", defaultEnvVar("CUBBY_PATH", "/vault-token"), "Path to key in cubbyhole. By default this is /vault-token.")

	flag.StringVar(&config.WrappedTokenAuth.TempToken, "wrapped-token-auth", defaultEnvVar("WRAPPED_TOKEN_AUTH", ""), "Temporary vault authorization token that has a wrapped permanent vault token.")

	flag.StringVar(&config.AppIdAuth.AppId, "auth-appid", defaultEnvVar("APP_ID", ""), "Vault App Id for authenication. (Overrides the APP_ID environment variable if set.)")
	flag.StringVar(&config.AppIdAuth.UserIdMethod, "auth-userid-method", defaultEnvVar("USER_ID_METHOD", ""), "Vault User Id authenication method (either 'mac' or 'file'). (Overrides the USER_ID_METHOD environment variable if set.)")
	flag.StringVar(&config.AppIdAuth.UserIdInterface, "auth-userid-interface", defaultEnvVar("USER_ID_INTERFACE", ""), "Network interface for 'mac' user id authenication method. (Overrides the USER_ID_INTERFACE environment variable if set.)")
	flag.StringVar(&config.AppIdAuth.UserIdPath, "auth-userid-path", defaultEnvVar("USER_ID_PATH", ""), "File path for 'file' user id authenication method. (Overrides the USER_ID_PATH environment variable if set.)")
	flag.StringVar(&config.AppIdAuth.UserIdHash, "auth-userid-hash", defaultEnvVar("USER_ID_HASH", ""), "Hash the user id with the following algorithim (sha256, sha1, md5). The hex representation of the hash will be used. (Overrides the USER_ID_HASH environment variable if set.)")
	flag.StringVar(&config.AppIdAuth.UserIdSalt, "auth-userid-salt", defaultEnvVar("USER_ID_SALT", ""), "If hashing, salt the hash in the format 'salt$user_id'. (Overrides the USER_ID_SALT environment variable if set.)")

	flag.BoolVar(&config.SelfRecreate, "self-recreate-token", func() bool {
		b, err := strconv.ParseBool(defaultEnvVar("RECREATE_TOKEN", "0"))
		return err == nil && b
	}(), "When the current token is reaching it's MAX_TTL (720h by default), recreate the token with the same policy instead of trying to renew (requires a sudo/root token, and for the token to have a ttl).")

	if d, err := time.ParseDuration(defaultEnvVar("TASK_LIFE", "2m")); err == nil {
		flag.DurationVar(&config.MaxTaskLife, "task-life", d, "The maximum amount of time that a task can be alive during which it can ask for a authorization token.")
	} else {
		panic(d)
	}
}

func recreateToken(token string, policies []string, ttl int) (string, error) {
	tokenOpts := struct {
		Ttl      string            `json:"ttl,omitempty"`
		Policies []string          `json:"policies"`
		Meta     map[string]string `json:"meta,omitempty"`
		NumUses  int               `json:"num_uses"`
		NoParent bool              `json:"no_parent"`
	}{time.Duration(time.Duration(ttl) * time.Second).String(), policies, map[string]string{"info": "auto-created"}, 0, true}
	if newToken, err := createToken(token, tokenOpts); err == nil {
		state.Lock()
		state.Token = newToken
		state.Unlock()
		return newToken, nil
	} else {
		return "", err
	}
}

func renew(token string, ttl int) error {
	r, err := VaultRequest{goreq.Request{
		Uri: vaultPath("/v1/auth/token/renew-self", ""),
		Body: struct {
			Increment int `json:"increment"`
		}{ttl},
		Method:          "POST",
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", token)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			return nil
		default:
			var e vaultError
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

func renew_worker(token string, onUnsealed <-chan struct{}) {
	creationTtl := 0
	for {
		r, err := VaultRequest{goreq.Request{
			Uri:             vaultPath("/v1/auth/token/lookup-self", ""),
			MaxRedirects:    10,
			RedirectHeaders: true,
		}.WithHeader("X-Vault-Token", token)}.Do()
		if err == nil {
			defer r.Body.Close()
			if r.StatusCode == 200 {
				var tokenInfo struct {
					Data struct {
						Ttl         int      `json:"ttl"`
						CreationTtl int      `json:"creation_ttl"`
						Policies    []string `json:"policies"`
					} `json:"data"`
				}
				if err := r.Body.FromJsonTo(&tokenInfo); err == nil {
					if creationTtl != 0 {
						if config.SelfRecreate && (creationTtl-tokenInfo.Data.Ttl) > 10 {
							// we are hitting the max_ttl on this token
							log.Println("Tried to renew token, and the new ttl was more than 10 seconds shorter than the expected ttl.")
							if newToken, err := recreateToken(token, tokenInfo.Data.Policies, creationTtl); err == nil {
								log.Println("Recreated new token.")
								token = newToken
								continue
							} else {
								log.Printf("Failed to create new token. The gatekeeper will be sealed when the next renew fails. Error: %v", err)
							}
						}
					}
					if tokenInfo.Data.CreationTtl == 0 {
						log.Println("Token has Creation TTL of 0. No need for renew.")
						return
					}
					creationTtl = tokenInfo.Data.CreationTtl
					if tokenInfo.Data.Ttl > 5 {
						tokenInfo.Data.Ttl -= 5
					}
					select {
					case <-time.After(time.Duration(tokenInfo.Data.Ttl) * time.Second):
						log.Printf("Renewing token with ttl of %v.", time.Duration(tokenInfo.Data.CreationTtl)*time.Second)
						if err := renew(token, tokenInfo.Data.CreationTtl); err == nil {
							log.Printf("Renewed token with ttl of %v.", time.Duration(tokenInfo.Data.CreationTtl)*time.Second)
						} else {
							log.Println("Failed to renew token. Sealing gatekeeper.")
							seal()
							return
						}
					case <-onUnsealed:
						return
					}
				} else {
					log.Printf("Failed to unmarshal token. Not starting renewal watcher. Error: %s ", err)
					return
				}
			} else if r.StatusCode == 403 {
				log.Println("Token is no longer valid. Sealing gatekeeper.")
				seal()
				return
			} else {
				log.Printf("Failed to lookup token. Error Code: %d", r.StatusCode)
				return
			}
		} else {
			log.Printf("Failed to lookup token. Not starting renewal watcher. Error: %s ", err)
			return
		}
	}
}

func unseal(unsealer Unsealer) error {
	state.Lock()
	defer state.Unlock()
	if state.Status == StatusUnsealed {
		return errAlreadyUnsealed
	}
	if token, err := unsealer.Token(); err == nil {
		if err := (&activePolicies).Load(token); err != nil {
			log.Printf("Failed to load policies: %v", err)
			return err
		}
		log.Printf("The gate has been unsealed with method '%s'.", unsealer.Name())
		state.Token = token
		state.Status = StatusUnsealed
		state.OnSealed = make(chan struct{})
		go renew_worker(token, state.OnSealed)
		return nil
	} else {
		return err
	}
}

func seal() error {
	state.Lock()
	defer state.Unlock()
	if state.Status == StatusUnsealed {
		log.Println("The gate has been sealed.")
		close(state.OnSealed)
	}
	state.OnSealed = nil
	state.Token = ""
	state.Status = StatusSealed
	return nil
}

func vaultPath(path string, query string) string {
	u, _ := url.Parse(config.Vault.Server)
	u.Path = path
	u.RawQuery = query
	return u.String()
}

func intro() {
	fmt.Println(" __")
	fmt.Println("/__ _ _|_ _ |/  _  _ |_) _  __")
	fmt.Println("\\_|(_| |_(/_|\\ (/_(/_|  (/_ |")
	fmt.Println("github.com/channelmeter/vault-gatekeeper-mesos")
	fmt.Println("Version: " + gitNearestTag)
}

func main() {
	// gin-gonic disables the log flags
	log.SetFlags(log.LstdFlags)
	state.Status = StatusSealed
	state.Started = time.Now()
	flag.Parse()

	intro()

	if config.Vault.Insecure || config.Vault.CaPath != "" || config.Vault.CaCert != "" {
		tr := &http.Transport{
			Dial:            goreq.DefaultDialer.Dial,
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{},
		}
		if config.Vault.Insecure {
			tr.TLSClientConfig.InsecureSkipVerify = true
		}

		if config.Vault.CaPath != "" || config.Vault.CaCert != "" {
			LoadCA := func() (*x509.CertPool, error) {
				if config.Vault.CaPath != "" {
					return gatekeeper.LoadCAPath(config.Vault.CaPath)
				} else if config.Vault.CaCert != "" {
					return gatekeeper.LoadCACert(config.Vault.CaCert)
				}
				panic("invariant violation")
			}
			if certs, err := LoadCA(); err == nil {
				tr.TLSClientConfig.RootCAs = certs
			} else {
				log.Printf("Failed to read client certs.")
				log.Println("Error:", err)
				os.Exit(1)
			}
		}
		// TODO: Fallback to regular client when communicating with Mesos Master
		goreq.DefaultTransport = tr
		goreq.DefaultClient = &http.Client{Transport: goreq.DefaultTransport}
	}

	r := gin.Default()
	r.SetHTMLTemplate(statusPage)
	r.GET("/", Status)
	r.GET("/status.json", Status)
	r.POST("/seal", Seal)
	r.POST("/unseal", Unseal)
	r.POST("/token", Provide)
	r.POST("/policies/reload", ReloadPolicies)

	if os.Getenv("VAULT_TOKEN") != "" {
		log.Println("VAULT_TOKEN detected in environment, unsealing with token...")
		if err := unseal(TokenUnsealer{os.Getenv("VAULT_TOKEN")}); err != nil {
			log.Println("Failed to unseal using VAULT_TOKEN. Either unset VAULT_TOKEN or provide a valid VAULT_TOKEN.")
			log.Println("Error:", err)
			os.Exit(1)
		}
		log.Println("Unseal successful with token provided in VAULT_TOKEN.")
	} else if config.CubbyAuth.TempToken != "" {
		log.Println("Attempting to unseal with provided Cubbyhole token...")
		if err := unseal(config.CubbyAuth); err != nil {
			log.Println("Failed to unseal using Cubbyhole. Please make sure the Cubbyhole auth is correctly setup.")
			log.Println("Error:", err)
			os.Exit(1)
		}
		log.Println("Unseal successful with token provided by Cubbyhole.")
	} else if config.WrappedTokenAuth.TempToken != "" {
		log.Println("Attempting to unseal with Wrapped Token...")
		if err := unseal(config.WrappedTokenAuth); err != nil {
			log.Println("Failed to unseal using Wrapped Token. Please make sure the Wrapped Token auth is correctly setup.")
			log.Println("Error:", err)
			os.Exit(1)
		}
		log.Println("Unseal successful with Wrapped Token.")
	} else if config.AppIdAuth.AppId != "" {
		log.Println("Attempting to unseal with provided APP ID credentials, using user_id from '" + config.AppIdAuth.UserIdMethod + "'...")
		if err := unseal(config.AppIdAuth); err != nil {
			log.Println("Failed to unseal using APP ID credentials. Provide a valid APP ID credentials.")
			log.Println("Error:", err)
			os.Exit(1)
		}
		log.Println("Unseal successful with app-id credentials.")
	}
	log.Printf("Listening and serving on '%s'...", config.ListenAddress)

	runFunc := func() error {
		return r.Run(config.ListenAddress)
	}
	if config.TlsCert != "" || config.TlsKey != "" {
		runFunc = func() error {
			return r.RunTLS(config.ListenAddress, config.TlsCert, config.TlsKey)
		}
	}
	if err := runFunc(); err != nil {
		log.Println("Failed to start server. Error: " + err.Error())
		os.Exit(1)
	}
}
