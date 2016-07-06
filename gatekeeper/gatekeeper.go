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

	gkAddr, err := url.Parse(GatekeeperAddr)
	if err != nil {
		return "", err
	}
	gkAddr.Path = "/token"

	gkTaskID := struct {
		TaskId string `json:"task_id"`
	}{taskId}

	gkReq, err := json.Marshal(gkTaskID)
	if err != nil {
		return "", err
	}

	gkResp, err := HttpClient.Post(gkAddr.String(), "application/json", bytes.NewReader(gkReq))
	if err != nil {
		return "", err
	}
	defer gkResp.Body.Close()

	var gkTokResp struct {
		OK     bool   `json:"ok"`
		Token  string `json:"token"`
		Status string `json:"status"`
		Error  string `json:"error"`
	}

	if err := json.NewDecoder(gkResp.Body).Decode(&gkTokResp); err != nil {
		return "", err
	}

	if !gkTokResp.OK {
		return "", errors.New(gkTokResp.Error)
	}

	vaultAddr, err := url.Parse(VaultAddress)
	if err != nil {
		return "", err
	}
	vaultAddr.Path = "/v1/cubbyhole/vault-token"

	req, err := http.NewRequest("GET", vaultAddr.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("X-Vault-Token", gkTokResp.Token)

	vaultResp, err := HttpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer vaultResp.Body.Close()

	bodyDecoder := json.NewDecoder(vaultResp.Body)

	if vaultResp.StatusCode != 200 {
		var vaultErr VaultError
		vaultErr.Code = vaultResp.StatusCode
		if err := bodyDecoder.Decode(&vaultErr); err != nil {
			vaultErr.Errors = []string{"communication error."}
			return "", err
		}

		return "", vaultErr
	}

	vaultSecret := struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}{}

	if err := bodyDecoder.Decode(&vaultSecret); err != nil {
		return "", err
	}

	return vaultSecret.Data.Token, nil
}

func EnvRequestVaultToken() (string, error) {
	return RequestVaultToken(os.Getenv("MESOS_TASK_ID"))
}
