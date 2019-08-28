package gatekeeper

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/nemosupremo/vault-gatekeeper/scheduler"
	"github.com/nemosupremo/vault-gatekeeper/vault/unsealer"

	"github.com/franela/goreq"
	"github.com/go-chi/chi"
)

func (g *Gatekeeper) OkResponse(w http.ResponseWriter, message string) {
	resp := struct {
		Unsealed bool   `json:"unsealed"`
		Message  string `json:"message"`
	}{Unsealed: g.IsUnsealed()}
	resp.Message = message

	json.NewEncoder(w).Encode(resp)
}

func (g *Gatekeeper) ErrorResponse(w http.ResponseWriter, code int, err string) {
	resp := struct {
		Unsealed bool   `json:"unsealed"`
		Error    string `json:"error"`
	}{Unsealed: g.IsUnsealed()}
	resp.Error = err

	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}

func (g *Gatekeeper) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(NewLogger(nil))
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "application/json")
			next.ServeHTTP(w, r)
		})
	})

	r.Get("/", g.status)
	r.Get("/status", g.status)
	r.Post("/seal", g.seal)
	r.Post("/unseal", g.unseal)
	r.Post("/token", g.requestToken)
	r.Post("/policies/reload", g.reloadPolicies)

	return r
}

func (g *Gatekeeper) status(w http.ResponseWriter, r *http.Request) {
	var status struct {
		Id       string      `json:"id"`
		Stats    interface{} `json:"stats"`
		Uptime   string      `json:"uptime"`
		Unsealed bool        `json:"unsealed"`
		Started  time.Time   `json:"started"`
		Ok       bool        `json:"ok"`
		Version  string      `json:"version"`
		Peers    []peer      `json:"peers,omitempty"`
	}
	status.Id = g.PeerId
	status.Started = g.Started
	status.Uptime = time.Since(status.Started).String()
	stats := g.Stats
	status.Stats = stats
	status.Ok = true
	status.Version = g.config.Version
	status.Unsealed = g.IsUnsealed()

	var peers []peer
	for _, peer := range g.Peers() {
		peer.Address = peer.address()
		peers = append(peers, peer)
	}
	status.Peers = peers

	if status.Unsealed {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(status)
}

func (g *Gatekeeper) seal(w http.ResponseWriter, r *http.Request) {
	g.Seal()
	g.OkResponse(w, "Gatekeeper sealed.")
}

func (g *Gatekeeper) unseal(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Method string `json:"method"`

		Token string `json:"token"`

		PersonalToken string `json:"personal_token"`

		RoleId   string `json:"role_id"`
		SecretId string `json:"secret_id"`

		Role  string `json:"aws_role"`
		Nonce string `json:"aws_nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
		var uns unsealer.Unsealer
		switch body.Method {
		case "token":
			uns = unsealer.TokenUnsealer{
				AuthToken: body.Token,
			}
		case "token-wrapped":
			uns = unsealer.WrappedTokenUnsealer{
				TempToken: body.Token,
			}
		case "approle":
			uns = unsealer.AppRoleUnsealer{
				RoleId:   body.RoleId,
				SecretId: body.SecretId,
			}
		case "aws-ec2", "aws":
			uns = unsealer.AwsUnsealer{
				Role:  body.Role,
				Nonce: body.Nonce,
			}
		case "github":
			uns = unsealer.GitHubUnsealer{
				PersonalToken: body.PersonalToken,
			}
		default:
			g.ErrorResponse(w, http.StatusUnprocessableEntity, "Cannot unseal with unknown method: '"+body.Method+"'")
			return
		}
		if err := g.Unseal(uns); err == nil {
			g.OkResponse(w, "Unseal successful with the '"+uns.Name()+"' method.")
		} else {
			g.ErrorResponse(w, http.StatusUnauthorized, "Unseal failed with the '"+uns.Name()+"' method.")
		}
	} else {
		g.ErrorResponse(w, http.StatusBadRequest, "JSON body could not be decoded: "+err.Error())
	}
}

func (g *Gatekeeper) getVaultAddr() string {
	if g.config.LocalDevMode == true {
		return g.config.Vault.PublicAddr
	}
	return g.config.Vault.Address
}

func (g *Gatekeeper) requestToken(w http.ResponseWriter, r *http.Request) {
	log := GetLog(r)
	if r.Header.Get("Gatekeeper-Proxy") != "" {
		LogEntrySetField(r, "proxied", true)
	}
	var body struct {
		Scheduler string `json:"scheduler"`
		TaskId    string `json:"task_id"`
		Role      string `json:"role"`
	}
	if g.IsUnsealed() {
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			if token, ttl, err := g.RequestToken(body.Scheduler, body.TaskId, body.Role, r.RemoteAddr); err == nil {
				log.Debugf("Reponse Token: %s\n", token)
				resp := struct {
					Unsealed  bool   `json:"unsealed"`
					Token     string `json:"token"`
					Ttl       string `json:"ttl"`
					VaultAddr string `json:"vault_addr"`
				}{
					Unsealed:  g.IsUnsealed(),
					Token:     token,
					Ttl:       ttl.String(),
					VaultAddr: g.getVaultAddr(),
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(resp)
			} else {
				log.Debugf("Reponse Token Error: %v\n", err)
				switch err {
				case scheduler.ErrTaskNotFound, ErrHostMismatch:
					g.ErrorResponse(w, http.StatusUnauthorized, err.Error())
				case ErrTaskNotFresh, ErrRoleMismatch, ErrNoSuchRole:
					g.ErrorResponse(w, http.StatusForbidden, err.Error())
				case ErrMaxTokensGiven:
					g.ErrorResponse(w, http.StatusTooManyRequests, err.Error())
				default:
					g.ErrorResponse(w, http.StatusInternalServerError, err.Error())
				}
			}
		} else {
			g.ErrorResponse(w, http.StatusBadRequest, "JSON body could not be decoded: "+err.Error())
		}
	} else {
		if len(g.Peers()) > 0 && r.Header.Get("Gatekeeper-Proxy") == "" {
			for _, peer := range g.Peers() {
				if peer.Unsealed {
					req, err := goreq.Request{
						Uri:    peer.TokenUri(),
						Method: "POST",
						Body:   body,
					}.WithHeader("Gatekeeper-Proxy", g.PeerId).WithHeader("User-Agent", r.UserAgent()).Do()
					if err == nil {
						w.WriteHeader(req.StatusCode)
						io.Copy(w, req.Body)
						return
					} else {
						log.Warnf("Failed to communicate with peer %v: %v", peer, err)
						g.ErrorResponse(w, http.StatusServiceUnavailable, "Unable to provide token: Gatekeeper is sealed.")
						return
					}
				}
			}
		}
		g.ErrorResponse(w, http.StatusServiceUnavailable, "Unable to provide token: Gatekeeper is sealed.")
	}
}

func (g *Gatekeeper) reloadPolicies(w http.ResponseWriter, r *http.Request) {
	log := GetLog(r)
	if g.IsUnsealed() {
		log.Infof("Reloading policies...")
		if policies, err := g.loadPolicies(); err == nil {
			g.Lock()
			g.Policies = policies
			numPolicies := policies.Len()
			g.Unlock()
			if r.Header.Get("Gatekeeper-Proxy") == "" {
				for _, peer := range g.Peers() {
					if peer.Unsealed {
						req, err := goreq.Request{
							Uri:    peer.ReloadUri(),
							Method: "POST",
						}.WithHeader("Gatekeeper-Proxy", g.PeerId).WithHeader("User-Agent", r.UserAgent()).Do()
						if err != nil {
							log.Warnf("Failed to communicate with peer %s: %v", peer, err)
						} else {
							req.Body.Close()
						}
					}
				}
			}
			log.Infof("Policies reloaded. %d total policies.", numPolicies)
			g.OkResponse(w, "Policies reloaded. "+strconv.Itoa(numPolicies)+" total policies.")
		} else {
			log.Warnf("Failed to reload policies: %v", err)
			g.ErrorResponse(w, http.StatusInternalServerError, "There was an error attempting to reload the policies. Please check the gatekeeper logs for more info.")
		}
	} else {
		g.ErrorResponse(w, http.StatusServiceUnavailable, "Failed to reload policies: gatekeeper is sealed.")
	}
}
