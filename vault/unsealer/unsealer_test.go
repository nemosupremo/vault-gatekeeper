package unsealer

import (
	"os"
	"testing"

	"vault-gatekeeper/vault"

	"github.com/franela/goreq"
	"github.com/segmentio/ksuid"
	"github.com/spf13/viper"
)

var vaultToken = os.Getenv("VAULT_TOKEN")
var vaultAddr = os.Getenv("VAULT_ADDR")

func init() {
	if vaultAddr == "" {
		vaultAddr = "http://localhost:8200"
	}
	viper.SetDefault("vault-addr", vaultAddr)
}

func TestTokenUnseal(t *testing.T) {
	if _, err := (&TokenUnsealer{vaultToken}).Token(); err != nil {
		t.Fatalf("Token Unseal Failed: %v", err)
	}
}

func TestWrappedTokenUnseal(t *testing.T) {
	r, err := vault.Request{
		goreq.Request{
			Uri:    vault.Path("/v1/auth/token/create"),
			Method: "POST",
			Body: struct {
				Ttl       string            `json:"ttl,omitempty"`
				Policies  []string          `json:"policies"`
				Meta      map[string]string `json:"meta,omitempty"`
				NumUses   int               `json:"num_uses"`
				NoParent  bool              `json:"no_parent"`
				Renewable bool              `json:"renewable"`
			}{"10s", []string{"unseal"}, nil, 0, true, true},
			MaxRedirects:    10,
			RedirectHeaders: true,
		}.WithHeader("X-Vault-Token", vaultToken).WithHeader("X-Vault-Wrap-TTL", "10s"),
	}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			var tk struct {
				Auth struct {
					ClientToken   string `json:"client_token"`
					LeaseDuration int    `json:"lease_duration"`
					TTL           int    `json:"ttl"`
				} `json:"auth"`
				WrapInfo struct {
					Token           string `json:"token"`
					TTL             int    `json:"ttl"`
					WrappedAccessor string `json:"wrapped_accessor"`
				} `json:"wrap_info"`
			}
			if err := r.Body.FromJsonTo(&tk); err != nil {
				t.Fatal("Could not create wrapped token.")
			}
			if _, err := (&WrappedTokenUnsealer{tk.WrapInfo.Token}).Token(); err != nil {
				t.Fatalf("Wrapped Token Unseal Failed: %v", err)
			}
		default:
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				t.Fatalf("Could not create wrapped token: %v", e.Errors)
			} else {
				t.Fatal("Could not create wrapped token.")
			}
		}
	} else {
		t.Fatal("Could not reach vault server.")
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

func TestUserPassUnseal(t *testing.T) {
	var authPath string
	if ap, err := createAuthEndpoint("userpass"); err == nil {
		authPath = ap
	} else {
		t.Fatalf("Failed to initialize userpass endpoint: %v", err)
	}

	vaultUser := ksuid.New().String()
	vaultPass := ksuid.New().String()
	r, err := vault.Request{goreq.Request{
		Uri:             vault.Path("/v1/auth/" + authPath + "/users/" + vaultUser),
		MaxRedirects:    10,
		RedirectHeaders: true,
		Body: struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Policies string `json:"policies"`
		}{vaultUser, vaultPass, "unseal"},
		ContentType: "application/json",
		Method:      "POST",
	}.WithHeader("X-Vault-Token", vaultToken)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200, 204:
			if _, err := (&UserPassUnsealer{Username: vaultUser, Password: vaultPass, Endpoint: authPath}).Token(); err != nil {
				t.Fatalf("UserPass Unseal Failed: %v", err)
			}
		default:
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				t.Fatalf("Could not create sample user for vault: %v", e.Errors)
			} else {
				t.Fatal("Could not create sample user for vault.")
			}
		}
	} else {
		t.Fatal("Could not reach vault server.")
	}

}

func TestAppRoleUnseal(t *testing.T) {
	var authPath string
	if ap, err := createAuthEndpoint("approle"); err == nil {
		authPath = ap
	} else {
		t.Fatalf("Failed to initialize approle endpoint: %v", err)
	}

	appRoleName := ksuid.New().String()

	//vaultPass := ksuid.New().String()
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
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200, 204:
			r, err := vault.Request{goreq.Request{
				Uri:             vault.Path("/v1/auth/" + authPath + "/role/" + appRoleName + "/role-id"),
				MaxRedirects:    10,
				RedirectHeaders: true,
			}.WithHeader("X-Vault-Token", vaultToken)}.Do()
			if err == nil && r.StatusCode == 200 {
				var roleId struct {
					Data struct {
						RoleId string `json:"role_id"`
					} `json:"data"`
				}
				r.Body.FromJsonTo(&roleId)

				r, err := vault.Request{goreq.Request{
					Uri:             vault.Path("/v1/auth/" + authPath + "/role/" + appRoleName + "/secret-id"),
					MaxRedirects:    10,
					RedirectHeaders: true,
					Method:          "POST",
				}.WithHeader("X-Vault-Token", vaultToken)}.Do()
				if err == nil && r.StatusCode == 200 {
					var secretId struct {
						Data struct {
							SecretId string `json:"secret_id"`
						} `json:"data"`
					}
					r.Body.FromJsonTo(&secretId)

					if _, err := (&AppRoleUnsealer{RoleId: roleId.Data.RoleId, SecretId: secretId.Data.SecretId, Endpoint: authPath}).Token(); err != nil {
						t.Fatalf("AppRoleUnseal Unseal Failed: %v", err)
					}
				} else {
					t.Fatal("Could not reach generate secret.")
				}
			} else if err == nil {
				var e vault.Error
				e.Code = r.StatusCode
				if err := r.Body.FromJsonTo(&e); err == nil {
					t.Fatalf("Could not retrieve role id for vault: %v", e.Errors)
				} else {
					t.Fatal("Could not retrieve role id for vault.")
				}
			} else {
				t.Fatal("Could not reach vault server.")
			}

		default:
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				t.Fatalf("Could not create sample role for vault: %v", e.Errors)
			} else {
				t.Fatal("Could not create sample role for vault.")
			}
		}
	} else {
		t.Fatal("Could not reach vault server.")
	}

}
