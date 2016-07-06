package gatekeeper

type gkTokenReq struct {
	TaskId string `json:"task_id"`
}

type gkTokenResp struct {
	OK     bool   `json:"ok"`
	Token  string `json:"token"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

type vaultSecret struct {
	Data vaultSecretData `json:"data"`
}

type vaultSecretData struct {
	Token string `json:"token"`
}
