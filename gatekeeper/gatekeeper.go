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
	capath := os.Getenv("VAULT_CAPATH")
	cacert := os.Getenv("VAULT_CACERT")
	var rootCas *x509.CertPool

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
			rootCas = certs
		} else {
			fmt.Fprintf(os.Stderr, "Gatekeeper: Failed to read client certs. Error: %v\n", err)
		}
	}

	var err error
	DefaultClient, err = NewClient(os.Getenv("VAULT_ADDR"), os.Getenv("GATEKEEPER_ADDR"), rootCas)
	if err == nil {
		if b, err := strconv.ParseBool(os.Getenv("VAULT_SKIP_VERIFY")); err == nil && b {
			DefaultClient.InsecureSkipVerify(true)
		}
	}
}

func RequestVaultToken(taskId string) (string, error) {
	return DefaultClient.RequestVaultToken(taskId)
}

func EnvRequestVaultToken() (string, error) {
	return DefaultClient.RequestVaultToken(os.Getenv("MESOS_TASK_ID"))
}

func NewClient(vaultAddress, gatekeeperAddress string, certPool *x509.CertPool) (*Client, error) {
	client := new(Client)
	client.VaultAddress = vaultAddress
	client.GatekeeperAddress = gatekeeperAddress
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{},
	}
	if certPool != nil {
		tr.TLSClientConfig.RootCAs = certPool
	}
	client.HttpClient = &http.Client{Transport: tr}
	if _, err := url.Parse(client.GatekeeperAddress); err != nil {
		return nil, err
	}
	if _, err := url.Parse(client.VaultAddress); err != nil {
		return nil, err
	}
	return client, nil
}

func (c *Client) InsecureSkipVerify(skipVerify bool) {
	if _, ok := c.HttpClient.Transport.(*http.Transport); ok {
		c.HttpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = skipVerify
	}
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

	var vaultWrappedResp vaultWrappedResponse

	if err := json.NewDecoder(vaultResp.Body).Decode(&vaultWrappedResp); err != nil {
		return "", err
	}

	secretResp := struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}{}

	if err := vaultWrappedResp.Unwrap(&secretResp); err != nil {
		return "", err
	}

	return secretResp.Auth.ClientToken, nil
}
