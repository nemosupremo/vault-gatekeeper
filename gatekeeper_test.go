package main

import (
	"flag"
	"fmt"
	"github.com/franela/goreq"
	"github.com/gin-gonic/gin"
	"os"
	"testing"
)

var (
	flagMesosAddr    = flag.String("mesos_master", os.Getenv("MINIMESOS_MASTER"), "Mesos Master Address")
	flagMarathonAddr = flag.String("marathon", os.Getenv("MINIMESOS_MARATHON"), "Marathon Address")
	flagZkAddr       = flag.String("zk", os.Getenv("MINIMESOS_ZOOKEEPER"), "Zookeeper Address")
	flagVaultToken   = flag.String("token", os.Getenv("VAULT_TOKEN"), "Vault Token")
)

const (
	vaultUser         = "gktest"
	vaultPass         = "gk-test"
	vaultUnsealPolicy = `// Policy Reading
path "secret/gatekeeper" {
	capabilities = ["read"]
}`
	sampleGkPolicy = `{
	    "app1":{
	        "policies":["app1"],
	        "meta":{"foo":"bar"},
	        "ttl":3000,
	        "num_uses":0
	    },
	    "*":{
	        "policies":["default"],
	        "ttl":1500
	    }
	}`
	gkListenAddress = "127.0.0.1:8765"
)

func TestMain(m *testing.M) {
	r, err := VaultRequest{goreq.Request{
		Uri:             vaultPath("/v1/secret/gatekeeper", ""),
		MaxRedirects:    10,
		RedirectHeaders: true,
		Body:            sampleGkPolicy,
		ContentType:     "application/json",
		Method:          "POST",
	}.WithHeader("X-Vault-Token", *flagVaultToken)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200, 204:
			//
		default:
			var e vaultError
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				panic(fmt.Sprintf("Could not set policies vault: %v", e.Errors))
			} else {
				panic("Could not set policies in vault.")
			}
		}
	} else {
		panic("Could not reach vault server: " + err.Error())
	}

	r, err = VaultRequest{goreq.Request{
		Uri:             vaultPath("/v1/sys/policy/unseal", ""),
		MaxRedirects:    10,
		RedirectHeaders: true,
		Body: struct {
			Rules string `json:"rules"`
		}{vaultUnsealPolicy},
		ContentType: "application/json",
		Method:      "POST",
	}.WithHeader("X-Vault-Token", *flagVaultToken)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200, 204:
			//
		default:
			var e vaultError
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				panic(fmt.Sprintf("Could not create token policies in vault: %v", e.Errors))
			} else {
				panic("Could not create token policies in vault.")
			}
		}
	} else {
		panic("Could not reach vault server: %s" + err.Error())
	}

	{
		config.ListenAddress = gkListenAddress
		r := gin.Default()
		r.SetHTMLTemplate(statusPage)
		r.GET("/", Status)
		r.GET("/status.json", Status)
		r.POST("/seal", Seal)
		r.POST("/unseal", Unseal)
		r.POST("/token", Provide)
		r.POST("/policies/reload", ReloadPolicies)

		go func() {
			//log.Printf("Listening and serving on '%s'...", config.ListenAddress)
			if err := r.Run(config.ListenAddress); err != nil {
				panic("Failed to start server. Error: " + err.Error())
			}
		}()
	}

	os.Exit(m.Run())
}

func TestTokenUnseal(t *testing.T) {
	seal()
	if err := unseal(TokenUnsealer{*flagVaultToken}); err != nil {
		t.Fatalf("Token Unseal Failed: %v", err)
	}
}

func TestWrappedTokenUnseal(t *testing.T) {
	r, err := VaultRequest{
		goreq.Request{
			Uri:    vaultPath("/v1/auth/token/create", ""),
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
		}.WithHeader("X-Vault-Token", *flagVaultToken).WithHeader("X-Vault-Wrap-TTL", "10"),
	}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			tk := vaultTokenResp{}
			if err := r.Body.FromJsonTo(&tk); err != nil {
				t.Fatal("Could not create wrapped token.")
			}
			seal()
			if err := unseal(WrappedTokenUnsealer{tk.WrapInfo.Token}); err != nil {
				t.Fatalf("Wrapped Token Unseal Failed: %v", err)
			}
		default:
			var e vaultError
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

func TestUserPassUnseal(t *testing.T) {
	r, err := VaultRequest{goreq.Request{
		Uri:             vaultPath("/v1/auth/userpass/users/"+vaultUser, ""),
		MaxRedirects:    10,
		RedirectHeaders: true,
		Body: struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Policies string `json:"policies"`
		}{vaultUser, vaultPass, "unseal"},
		ContentType: "application/json",
		Method:      "POST",
	}.WithHeader("X-Vault-Token", *flagVaultToken)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200, 204:
			//
		default:
			var e vaultError
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

	seal()
	if err := unseal(UserpassUnsealer{Username: vaultUser, Password: vaultPass}); err != nil {
		t.Fatalf("UserPass Unseal Failed: %v", err)
	}
}

func TestCubbyUnseal(t *testing.T) {
	t.Skip("Deprecated")
}

func TestAppIdUnseal(t *testing.T) {
	t.Skip("TODO")
}

func TestGitHubUnseal(t *testing.T) {
	t.Skip("TODO")
}
