package usagestore

import (
	"os"
	"path"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/packetloop/vault-gatekeeper/vault"

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

func TestVaultStore(t *testing.T) {
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

	storePath := path.Join(secretPath, "data", ksuid.New().String())
	vs, _ := NewVaultStore(storePath)

	if err := vs.Acquire(vaultToken, "k", 1, 10*time.Minute); err == nil {
		if n, err := vs.UsageCount(vaultToken, "k"); err == nil {
			if n != 1 {
				t.Fatalf("expected usage to be 1, got %d", n)
			}
		} else {
			t.Fatalf("failed to acquire usage count for sample key k: %v", err)
		}
		if err := vs.Acquire(vaultToken, "k", 1, 10*time.Minute); err != ErrPutLimitExceeded {
			t.Fatalf("Expected ErrPutLimitExceeded but got: %v", err)
		}
		c := make(chan struct{})
		expectedSuccess := int32(10)
		success := int32(0)
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				<-c
				if err := vs.Acquire(vaultToken, "g", int(expectedSuccess), 10*time.Minute); err == nil {
					atomic.AddInt32(&success, 1)
				} else if err == ErrPutLimitExceeded {

				} else {
					t.Fatalf("Error when trying to acquire in stampede: %v", err)
				}
				wg.Done()
			}()
		}
		close(c)
		wg.Wait()
		if expectedSuccess != success {
			t.Fatalf("Expected %d acquires to succeed but got: %d", expectedSuccess, success)
		}
	} else {
		t.Fatalf("failed to acquire sample key k: %v", err)
	}

}
