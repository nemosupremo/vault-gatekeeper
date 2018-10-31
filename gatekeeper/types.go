package gatekeeper

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type VaultError struct {
	Code   int      `json:"-"`
	Errors []string `json:"errors"`
}

func (e VaultError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, strings.Join(e.Errors, ", "))
}

func buildVaultError(resp *http.Response) error {
	if resp.StatusCode == 200 {
		return nil
	}

	vaultErr := &VaultError{Code: resp.StatusCode}
	if err := json.NewDecoder(resp.Body).Decode(vaultErr); err != nil {
		vaultErr.Errors = []string{"communication error", err.Error()}
	}

	return vaultErr
}

type gkTokenReq struct {
	TaskId string `json:"task_id"`
}

type gkTokenResp struct {
	Unsealed  bool   `json:"unsealed"`
	Token     string `json:"token"`
	Ttl       string `json:"ttl"`
	VaultAddr string `json:"vault_addr"`
}

type vaultWrappedResponse struct {
	Data struct {
		WrappedSecret string `json:"response"`
	} `json:"data"`
}

func (vr *vaultWrappedResponse) Unwrap(v interface{}) error {
	return json.Unmarshal([]byte(vr.Data.WrappedSecret), v)
}

type GatekeeperStatus struct {
	OK      bool                   `json:"ok"`
	Started string                 `json:"started"`
	Status  string                 `json:"status"`
	Uptime  string                 `json:"uptime"`
	Stats   map[string]interface{} `json:"stats"`
}

type UnsealRequest struct {
	Type            string `json:"type"`
	Token           string `json:"token"`
	CubbyPath       string `json:"cubby_path"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	AppID           string `json:"app_id"`
	UserIdMethod    string `json:"user_id_method"`
	UserIdInterface string `json:"user_id_interface"`
	UserIdPath      string `json:"user_id_path"`
	UserIdHash      string `json:"user_id_hash"`
	UserIdSalt      string `json:"user_id_salt"`
}

type GatekeeperResponse struct {
	OK     bool   `json:"ok"`
	Status string `json:"status"`
	Error  string `json:"error"`
}
