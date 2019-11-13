package gatekeeper

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nemosupremo/vault-gatekeeper/policy"
	"github.com/nemosupremo/vault-gatekeeper/scheduler"
	"github.com/nemosupremo/vault-gatekeeper/scheduler/mock"
	"github.com/nemosupremo/vault-gatekeeper/vault"
	"github.com/nemosupremo/vault-gatekeeper/vault/unsealer"

	"github.com/franela/goreq"
	"github.com/segmentio/ksuid"
	"github.com/spf13/viper"
)

const rootPolicy = `{
	"*":{
		"roles":["wildcard"],
		"num_uses": 1
	},
	"x":{
		"roles":["invalid"],
		"num_uses": 1
	}
}`

const subPolicy = `{
	"foo":{
		"roles":["bar"],
		"num_uses": 2
	},
	"x":{
		"roles":["valid"],
		"num_uses": 1
	}
}`

var vaultToken = os.Getenv("VAULT_TOKEN")
var vaultAddr = os.Getenv("VAULT_ADDR")

func init() {
	if vaultAddr == "" {
		vaultAddr = "http://localhost:8200"
	}
	viper.SetDefault("vault-addr", vaultAddr)
}

func TestLoadPolicyV2(t *testing.T) {
	secretPath := ksuid.New().String()
	r, err := vault.Request{
		goreq.Request{
			Uri:    vault.Path("/v1/sys/mounts/" + secretPath),
			Method: "POST",
			Body: struct {
				Type    string            `json:"type"`
				Options map[string]string `json:"options"`
			}{"kv", map[string]string{"version": "2"}},
			MaxRedirects:    10,
			RedirectHeaders: true,
		}.WithHeader("X-Vault-Token", vaultToken),
	}.Do()
	if err != nil || (r.StatusCode != 200 && r.StatusCode != 204) {
		t.Fatalf("failed to mount v2 secret backend.")
	}

	pathKey := ksuid.New().String()
	for i, policy := range []string{rootPolicy, subPolicy} {
		var path string
		switch i {
		case 0:
			path = "/v1/" + secretPath + "/data/" + pathKey
		case 1:
			path = "/v1/" + secretPath + "/data/" + pathKey + "/foo/bar"
		default:
			t.Fatalf("misconfigured test.")
		}
		if err := installPolicy(path, policy); err != nil {
			if verr, ok := err.(vault.Error); ok {
				t.Fatalf("Could not upload policy to vault: %v", verr)
			} else {
				t.Fatalf("Failed to upload policy to vault: %v", err)
			}
		}
	}

	g := &Gatekeeper{}
	g.config.PolicyPath = "/v1/" + secretPath + "/data/" + pathKey
	g.config.Vault.KvVersion = "2"
	g.Token = vaultToken
	if policies, err := g.loadPolicies(); err == nil {
		mustGet := func(p *policy.Policy, ok bool) *policy.Policy {
			if ok {
				return p
			}
			t.Fatalf("Did not find a matching policy")
			return nil
		}
		if !mustGet(policies.Get("default")).Has("wildcard") {
			t.Fatalf("Expected default role to have wildcard.")
		}
		if !mustGet(policies.Get("foo")).Has("bar") {
			t.Fatalf("Expected foo policy to have bar role.")
		}
		if mustGet(policies.Get("x")).Has("invalid") {
			t.Fatalf("Expected x policy to not have invalid role.")
		}
		if !mustGet(policies.Get("x")).Has("valid") {
			t.Fatalf("Expected x policy to have valid role.")
		}
	} else {
		t.Fatalf("Loading policies failed: %v", err)
	}
}

func TestLoadPolicyV1(t *testing.T) {
	secretPath := ksuid.New().String()
	r, err := vault.Request{
		goreq.Request{
			Uri:    vault.Path("/v1/sys/mounts/" + secretPath),
			Method: "POST",
			Body: struct {
				Type    string            `json:"type"`
				Options map[string]string `json:"options"`
			}{"kv", map[string]string{"version": "1"}},
			MaxRedirects:    10,
			RedirectHeaders: true,
		}.WithHeader("X-Vault-Token", vaultToken),
	}.Do()
	if err != nil || (r.StatusCode != 200 && r.StatusCode != 204) {
		t.Fatalf("failed to mount v1 secret backend.")
	}

	pathKey := ksuid.New().String()
	for i, policy := range []string{rootPolicy, subPolicy} {
		var path string
		switch i {
		case 0:
			path = "/v1/" + secretPath + "/" + pathKey
		case 1:
			path = "/v1/" + secretPath + "/" + pathKey + "/foo/bar"
		default:
			t.Fatalf("misconfigured test.")
		}
		if err := installPolicy(path, policy); err != nil {
			if verr, ok := err.(vault.Error); ok {
				t.Fatalf("Could not upload policy to vault: %v", verr)
			} else {
				t.Fatalf("Failed to upload policy to vault: %v", err)
			}
		}
	}

	g := &Gatekeeper{}
	g.config.PolicyPath = "/v1/" + secretPath + "/" + pathKey
	g.config.Vault.KvVersion = "1"
	g.Token = vaultToken
	if policies, err := g.loadPolicies(); err == nil {
		mustGet := func(p *policy.Policy, ok bool) *policy.Policy {
			if ok {
				return p
			}
			t.Fatalf("Did not find a matching policy")
			return nil
		}
		if !mustGet(policies.Get("default")).Has("wildcard") {
			t.Fatalf("Expected default role to have wildcard.")
		}
		if !mustGet(policies.Get("foo")).Has("bar") {
			t.Fatalf("Expected foo policy to have bar role.")
		}
		if mustGet(policies.Get("x")).Has("invalid") {
			t.Fatalf("Expected x policy to not have invalid role.")
		}
		if !mustGet(policies.Get("x")).Has("valid") {
			t.Fatalf("Expected x policy to have valid role.")
		}
	} else {
		t.Fatalf("Loading policies failed: %v", err)
	}
}

func installPolicy(path string, policy string) error {
	r, err := vault.Request{
		goreq.Request{
			Uri:             vault.Path(path),
			MaxRedirects:    10,
			RedirectHeaders: true,
			Body: struct {
				Data json.RawMessage `json:"data"`
			}{json.RawMessage(policy)},
			ContentType: "application/json",
			Method:      "POST",
		}.WithHeader("X-Vault-Token", vaultToken),
	}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200, 204:
			return nil
		default:
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return e
			} else {
				return err
			}
		}
	} else {
		return err
	}
}

func createAuthEndpoint(authType string) (string, error) {
	authPath := ksuid.New().String()
	r, err := vault.Request{
		goreq.Request{
			Uri:    vault.Path("/v1/sys/auth/" + authPath),
			Method: "POST",
			Body: struct {
				Type string `json:"type"`
			}{authType},
			MaxRedirects:    10,
			RedirectHeaders: true,
		}.WithHeader("X-Vault-Token", vaultToken),
	}.Do()
	if err == nil {
		defer r.Body.Close()
		if r.StatusCode == 200 || r.StatusCode == 204 {
			return authPath, nil
		} else {
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return "", e
			} else {
				return "", err
			}
		}
	} else {
		return "", err
	}
}

const mockPolicy = `{
	"mock:*":{
		"roles":["test_role"],
		"num_uses":1
	},
	"mock:special":{
		"roles":["test_role", "{{name}}"],
		"num_uses":1
	}
}`

func TestRequestToken(t *testing.T) {
	mock.ValidTaskId = ksuid.New().String()

	var authPath string
	if ap, err := createAuthEndpoint("approle"); err == nil {
		authPath = ap
	} else {
		t.Fatalf("Failed to initialize approle endpoint: %v", err)
	}

	policyPath := "v1/secret/data/" + ksuid.New().String()
	for _, appRoleName := range []string{"mock", "test_role", "special"} {
		r, err := vault.Request{goreq.Request{
			Uri:             vault.Path("/v1/auth/" + authPath + "/role/" + appRoleName),
			MaxRedirects:    10,
			RedirectHeaders: true,
			Body: struct {
				Policies string `json:"policies"`
			}{"unseal"},
			ContentType: "application/json",
			Method:      "POST",
		}.WithHeader("X-Vault-Token", vaultToken)}.Do()

		if err != nil || (r.StatusCode != 200 && r.StatusCode != 204) {
			t.Fatalf("failed to create app role for testing")
		}
	}

	if err := installPolicy(policyPath, mockPolicy); err != nil {
		if verr, ok := err.(vault.Error); ok {
			t.Fatalf("Could not upload policy to vault: %v", verr)
		} else {
			t.Fatalf("Failed to upload policy to vault: %v", err)
		}
	}

	conf := Config{
		Schedulers: []string{"mock"},
		Store:      "memory",

		PolicyPath:  policyPath,
		MaxTaskLife: 1 * time.Minute,

		Unsealer: unsealer.TokenUnsealer{vaultToken},
	}

	conf.Vault.Address = vaultAddr
	conf.Vault.KvVersion = "2"
	conf.Vault.AppRoleMount = authPath

	if g, err := NewGatekeeper(conf); err == nil && g.IsUnsealed() {
		if token, _, err := g.RequestToken("mock", mock.ValidTaskId, "", ""); err == nil {
			if _, err := (unsealer.WrappedTokenUnsealer{token}).Token(); err != nil {
				t.Fatalf("Wrapped token requested from gatekeeper could not be unwrapped: %v", err)
			}
		} else {
			t.Fatalf("Failed to request token: %v", err)
		}

		if _, _, err := g.RequestToken("mock", mock.ValidTaskId, "", ""); err != ErrMaxTokensGiven {
			t.Fatalf("Token request should have failed with ErrMaxTokensGiven: %v", err)
		}

		mock.ValidTaskId = ksuid.New().String()
		if _, _, err := g.RequestToken("mock", mock.ValidTaskId, "super-role", ""); err != ErrRoleMismatch {
			t.Fatalf("Token request should have failed with ErrRoleMismatch: %v", err)
		}

		mock.ValidTaskId = ksuid.New().String()
		if _, _, err := g.RequestToken("mock", mock.ValidTaskId, "{{name}}", ""); err != ErrRoleMismatch {
			t.Fatalf("Token request should have failed with ErrRoleMismatch: %v", err)
		}

		mock.ValidTaskId = "special"
		if _, _, err := g.RequestToken("mock", mock.ValidTaskId, "{{name}}", ""); err != nil {
			t.Fatalf("Token request should have succeeded with {{name}}: %v", err)
		}

		mock.ValidTaskId = "localhost"
		g.config.HostCheck = true
		if _, _, err := g.RequestToken("mock", mock.ValidTaskId, "", "localhost"); err != nil {
			t.Fatalf("Token request should have succeeded: %v", err)
		}
		if _, _, err := g.RequestToken("mock", mock.ValidTaskId, "", "172.217.9.78"); err != ErrHostMismatch {
			t.Fatalf("Token request should have failed with ErrHostMismatch: %v", err)
		}
		g.config.HostCheck = false

		if _, _, err := g.RequestToken("mock", ksuid.New().String(), "", ""); err != scheduler.ErrTaskNotFound {
			t.Fatalf("Unknown task should have failed: %v", err)
		}

		if _, _, err := g.RequestToken("mock", "expired", "", ""); err != ErrTaskNotFresh {
			t.Fatalf("Expired task should have returned task not fresh: %v", err)
		}
	} else if err == nil {
		t.Fatalf("Failed to create gatekeeper instance: could not unseal.")
	} else {
		t.Fatalf("Failed to create gatekeeper instance: %v", err)
	}

}
