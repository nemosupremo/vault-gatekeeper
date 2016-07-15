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

type Client struct {
	VaultAddress      string
	GatekeeperAddress string
	HttpClient        *http.Client
}

var DefaultClient *Client

var ErrNoTaskId = errors.New("No task id provided.")

func init() {
	DefaultClient = new(Client)
	DefaultClient.VaultAddress = os.Getenv("VAULT_ADDR")
	DefaultClient.GatekeeperAddress = os.Getenv("GATEKEEPER_ADDR")
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
	DefaultClient.HttpClient = &http.Client{Transport: tr}
}

func RequestVaultToken(taskId string) (string, error) {
	return DefaultClient.RequestVaultToken(taskId)
}

func EnvRequestVaultToken() (string, error) {
	return DefaultClient.RequestVaultToken(os.Getenv("MESOS_TASK_ID"))
}

func (c *Client) RequestVaultToken(taskId string) (string, error) {
	if c.HttpClient == nil {
		c.HttpClient = http.DefaultClient
	}
	tempToken, err := c.requestTempToken(taskId)
	if err != nil {
		return "", err
	}

	permToken, err := c.requestPermToken(tempToken)
	if err != nil {
		return "", err
	}

	return permToken, err
}

func (c *Client) requestTempToken(taskID string) (string, error) {
	if taskID == "" {
		return "", ErrNoTaskId
	}

	gkAddr, err := url.Parse(c.GatekeeperAddress)
	if err != nil {
		return "", err
	}
	gkAddr.Path = "/token"

	gkTaskID := gkTokenReq{TaskId: taskID}
	gkReq, err := json.Marshal(gkTaskID)
	if err != nil {
		return "", err
	}

	gkResp, err := c.HttpClient.Post(gkAddr.String(), "application/json", bytes.NewReader(gkReq))
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

func (c *Client) requestPermToken(tempToken string) (string, error) {
	vaultAddr, err := url.Parse(c.VaultAddress)
	if err != nil {
		return "", err
	}
	vaultAddr.Path = "/v1/cubbyhole/response"

	req, err := http.NewRequest("GET", vaultAddr.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("X-Vault-Token", tempToken)

	vaultResp, err := c.HttpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer vaultResp.Body.Close()

	if err := buildVaultError(vaultResp); err != nil {
		return "", err
	}

	cubbyholeSecret := &cubbyholeSecret{}
	if err := json.NewDecoder(vaultResp.Body).Decode(cubbyholeSecret); err != nil {
		return "", err
	}

	return cubbyholeSecret.Data.WrappedSecret.Token, nil
}
