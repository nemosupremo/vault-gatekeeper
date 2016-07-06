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
)

var HttpClient = &http.Client{}
var VaultAddress = os.Getenv("VAULT_ADDR")
var GatekeeperAddr = os.Getenv("GATEKEEPER_ADDR")

var ErrNoTaskId = errors.New("No task id provided.")

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
	tempToken, err := requestTempToken(taskId)
	if err != nil {
		return "", err
	}

	permToken, err := requestPermToken(tempToken)
	if err != nil {
		return "", err
	}

	return permToken, err
}

func requestTempToken(taskID string) (string, error) {
	if taskID == "" {
		return "", ErrNoTaskId
	}

	gkAddr, err := url.Parse(GatekeeperAddr)
	if err != nil {
		return "", err
	}
	gkAddr.Path = "/token"

	gkTaskID := gkTokenReq{TaskId: taskID}
	gkReq, err := json.Marshal(gkTaskID)
	if err != nil {
		return "", err
	}

	gkResp, err := HttpClient.Post(gkAddr.String(), "application/json", bytes.NewReader(gkReq))
	if err != nil {
		return "", err
	}
	defer gkResp.Body.Close()

	gkTokResp := &gkTokenResp{}
	if err := json.NewDecoder(gkResp.Body).Decode(gkTokResp); err != nil {
		return "", err
	}

	if !gkTokResp.OK {
		return "", errors.New(gkTokResp.Error)
	}

	return gkTokResp.Token, nil
}

func requestPermToken(tempToken string) (string, error) {
	vaultAddr, err := url.Parse(VaultAddress)
	if err != nil {
		return "", err
	}
	vaultAddr.Path = "/v1/cubbyhole/vault-token"

	req, err := http.NewRequest("GET", vaultAddr.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("X-Vault-Token", tempToken)

	vaultResp, err := HttpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer vaultResp.Body.Close()

	if err := buildVaultError(vaultResp); err != nil {
		return "", err
	}

	vaultSecret := &vaultSecret{}
	if err := json.NewDecoder(vaultResp.Body).Decode(vaultSecret); err != nil {
		return "", err
	}

	return vaultSecret.Data.Token, nil
}

func EnvRequestVaultToken() (string, error) {
	return RequestVaultToken(os.Getenv("MESOS_TASK_ID"))
}
