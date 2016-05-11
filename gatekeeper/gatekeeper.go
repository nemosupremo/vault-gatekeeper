package gatekeeper

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var HttpClient = &http.Client{}
var VaultAddress = os.Getenv("VAULT_ADDR")
var GatekeeperAddr = os.Getenv("GATEKEEPER_ADDR")

var ErrNoTaskId = errors.New("No task id provided.")

type VaultError struct {
	Code   int      `json:"-"`
	Errors []string `json:"errors"`
}

func (e VaultError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, strings.Join(e.Errors, ", "))
}

func init() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{},
	}
	capath := os.Getenv("VAULT_CAPATH")
	cacert := os.Getenv("VAULT_CACERT")

	if b, err := strconv.ParseBool(os.Getenv("VAULT_SKIP_VERIFY")); err == nil && b {
		tr.TLSClientConfig.InsecureSkipVerify = true
	}

	if capath != "" || cacert != "" {
		LoadCA := func() (*x509.CertPool, error) {
			if capath != "" {
				return LoadCAPath(capath)
			} else if cacert != "" {
				return LoadCACert(cacert)
			}
			panic("invariant violation")
		}
		if certs, err := LoadCA(); err == nil {
			tr.TLSClientConfig.RootCAs = certs
		} else {
			fmt.Fprintf(os.Stderr, "Gatekeeper: Failed to read client certs. Error: %v\n", err)
		}
	}
	HttpClient = &http.Client{Transport: tr}
}

func RequestVaultToken(taskId string) (string, error) {
	if taskId == "" {
		return "", ErrNoTaskId
	}
	var gkPath string
	var vaultPath string
	if u, err := url.Parse(GatekeeperAddr); err == nil {
		u.Path = "/token"
		gkPath = u.String()
	} else {
		return "", err
	}

	if u, err := url.Parse(VaultAddress); err == nil {
		u.Path = "/v1/cubbyhole/vault-token"
		vaultPath = u.String()
	} else {
		return "", err
	}

	gkb := struct {
		TaskId string `json:"task_id"`
	}{taskId}
	payload, _ := json.Marshal(gkb)

	var gkResp struct {
		Status string `json:"status"`
		Ok     bool   `json:"ok"`
		Error  string `json:"error"`
		Token  string `json:"token"`
	}

	if resp, err := HttpClient.Post(gkPath, "application/json", bytes.NewReader(payload)); err == nil {
		decoder := json.NewDecoder(resp.Body)
		if err := decoder.Decode(&gkResp); err == nil {
			if gkResp.Ok {
				req, _ := http.NewRequest("GET", vaultPath, nil)
				req.Header.Add("X-Vault-Token", gkResp.Token)
				if resp, err := HttpClient.Do(req); err == nil {
					decoder := json.NewDecoder(resp.Body)
					vaultResp := struct {
						Data struct {
							Token string `json:"token"`
						} `json:"data"`
					}{}
					if resp.StatusCode == 200 {
						if err := decoder.Decode(&vaultResp); err == nil {
							return vaultResp.Data.Token, nil
						} else {
							return "", err
						}
					} else {
						var e VaultError
						e.Code = resp.StatusCode
						if err := decoder.Decode(&e); err == nil {
							return "", e
						} else {
							e.Errors = []string{"communication error."}
							return "", e
						}
					}
				} else {
					return "", err
				}
			} else {
				return "", errors.New(gkResp.Error)
			}
		} else {
			return "", err
		}
	} else {
		return "", err
	}
}

func EnvRequestVaultToken() (string, error) {
	return RequestVaultToken(os.Getenv("MESOS_TASK_ID"))
}
