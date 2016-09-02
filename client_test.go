package main

import (
	"github.com/channelmeter/vault-gatekeeper-mesos/gatekeeper"
	"github.com/franela/goreq"
	"math/rand"
	"testing"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

func RandString(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func TestGateKeeperClient(t *testing.T) {
	seal()
	if err := unseal(TokenUnsealer{*flagVaultToken}); err != nil {
		t.Fatalf("Token Unseal Failed: %v", err)
	}

	client, err := gatekeeper.NewClient(config.Vault.Server, "http://"+gkListenAddress, nil)
	if err != nil {
		t.Fatalf("Failed to create gatekeeper client: %v", err)
	}
	client.InsecureSkipVerify(true)

	state.testingTaskId = RandString(32)
	if token, err := client.RequestVaultToken(state.testingTaskId); err != nil {
		t.Fatalf("Failed to request vault token: %v", err)
	} else {
		t.Logf("Got token using client: %s", token)
		r, err := VaultRequest{goreq.Request{
			Uri:             vaultPath("/v1/auth/token/lookup-self", ""),
			MaxRedirects:    10,
			RedirectHeaders: true,
		}.WithHeader("X-Vault-Token", token)}.Do()
		if err == nil {
			defer r.Body.Close()
			if r.StatusCode != 200 {
				t.Fatalf("Token recieved is not valid. Status Code: %d", r.StatusCode)
			}
		} else {
			t.Fatalf("Failed to lookup token. Error: %s ", err)
		}
	}
}
