package main

import (
	"fmt"
	"github.com/franela/goreq"
	"path"
)

type policyLoadError struct {
	Err error `json:"error"`
}

func (ple policyLoadError) Error() string {
	return fmt.Sprintf("Error loading policy from vault: %v", ple.Err)
}

type policy struct {
	Policies []string          `json:"policies"`
	Meta     map[string]string `json:"meta,omitempty"`
	Ttl      int               `json:"ttl,omitempty"`
	NumUses  int               `json:"num_users,omitempty"`
}

type policies map[string]*policy

var defaultPolicy = &policy{
	Ttl: 21600,
}
var activePolicies = make(policies)

func (p policies) Get(key string) *policy {
	if pol, ok := p[key]; ok {
		return pol
	} else if pol, ok := p["*"]; ok {
		return pol
	} else {
		return defaultPolicy
	}
}

func (p policies) Load(authToken string) error {
	r, err := goreq.Request{
		Uri:             vaultPath(path.Join("/v1/secret", config.Vault.GkPolicies), ""),
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", authToken).Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			resp := struct {
				Data policies `json:"data"`
			}{}
			if err := r.Body.FromJsonTo(&resp); err == nil {
				for k, _ := range p {
					delete(p, k)
				}
				for k, v := range resp.Data {
					p[k] = v
				}
				return nil
			} else {
				return policyLoadError{err}
			}
		default:
			var e vaultError
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return policyLoadError{e}
			} else {
				e.Errors = []string{"communication error."}
				return policyLoadError{e}
			}
		}
	} else {
		return policyLoadError{err}
	}
	return nil
}
