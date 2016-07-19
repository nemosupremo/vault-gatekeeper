package main

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"strings"
	"time"
)

func Status(c *gin.Context) {
	var opts struct {
		Stats          interface{} `json:"stats"`
		StatusUnsealed string      `json:"-"`
		StatusSealed   string      `json:"-"`
		Uptime         string      `json:"uptime"`
		Status         string      `json:"status"`
		Started        time.Time   `json:"started"`
		Ok             bool        `json:"ok"`
		Version        string      `json:"version"`
	}
	opts.Stats = state.Stats
	opts.Uptime = time.Now().Sub(state.Started).String()
	opts.Status = string(state.Status)
	opts.Started = state.Started
	opts.Ok = true
	opts.Version = gitNearestTag
	switch state.Status {
	case StatusSealed:
		opts.StatusSealed = "block"
		opts.StatusUnsealed = "none"
	case StatusUnsealed:
		opts.StatusSealed = "none"
		opts.StatusUnsealed = "block"
	}
	if strings.HasPrefix(c.Request.URL.Path, "/status.json") ||
		c.Request.Header.Get("accept") == "application/json" {
		c.JSON(200, opts)
		return
	}
	c.HTML(200, "status", opts)
	return
}

func Unseal(c *gin.Context) {
	var request struct {
		Type string `json:"type"`

		AppId           string `json:"app_id"`
		UserIdMethod    string `json:"user_id_method"`
		UserIdInterface string `json:"user_id_interface"`
		UserIdPath      string `json:"user_id_path"`
		UserIdHash      string `json:"user_id_hash"`
		UserIdSalt      string `json:"user_id_salt"`

		Token string `json:"token"`

		Username string `json:"username"`
		Password string `json:"password"`

		CubbyPath string `json:"cubby_path"`
	}
	switch c.Request.Header.Get("Content-Type") {
	case "application/x-www-form-urlencoded", "multipart/form-data":
		c.Request.ParseForm()
		request.Type = c.Request.FormValue("auth_type")
		switch request.Type {
		case "app-id":
			request.AppId = c.Request.FormValue("app-id_appid")
			request.UserIdMethod = c.Request.FormValue("app-id_userid_method")
			switch request.UserIdMethod {
			case "mac":
				request.UserIdInterface = c.Request.FormValue("app-id_userid_data")
			case "file":
				request.UserIdPath = c.Request.FormValue("app-id_userid_data")
			default:
				c.JSON(400, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Error  string `json:"error"`
				}{string(state.Status), false, errUnknownUserIdMethod.Error()})
			}
			request.UserIdHash = c.Request.FormValue("app-id_userid_hash")
			request.UserIdSalt = c.Request.FormValue("app-id_userid_salt")
		case "userpass":
			request.Username = c.Request.FormValue("userpass_username")
			request.Password = c.Request.FormValue("userpass_password")
		case "github":
			request.Token = c.Request.FormValue("github_token")
		case "token":
			request.Token = c.Request.FormValue("token_token")
		case "cubby":
			request.Token = c.Request.FormValue("cubby_token")
			request.CubbyPath = c.Request.FormValue("cubby_path")
		case "wrapped-token":
			request.Token = c.Request.FormValue("wrapped_token")
		default:
			c.JSON(400, struct {
				Status string `json:"status"`
				Ok     bool   `json:"ok"`
				Error  string `json:"error"`
			}{string(state.Status), false, errUnknownAuthMethod.Error()})
			return
		}
	case "application/json":
		decoder := json.NewDecoder(c.Request.Body)
		if err := decoder.Decode(&request); err != nil {
			c.JSON(400, struct {
				Status string `json:"status"`
				Ok     bool   `json:"ok"`
				Error  string `json:"error"`
			}{string(state.Status), false, err.Error()})
			return
		}
	}

	var unsealer Unsealer
	switch request.Type {
	case "app-id":
		unsealer = AppIdUnsealer{
			AppId:           request.AppId,
			UserIdMethod:    request.UserIdMethod,
			UserIdInterface: request.UserIdInterface,
			UserIdPath:      request.UserIdPath,
			UserIdHash:      request.UserIdHash,
			UserIdSalt:      request.UserIdSalt,
		}
	case "userpass":
		unsealer = UserpassUnsealer{
			Username: request.Username,
			Password: request.Password,
		}
	case "github":
		unsealer = GithubUnsealer{
			PersonalToken: request.Token,
		}
	case "token":
		unsealer = TokenUnsealer{
			AuthToken: request.Token,
		}
	case "cubby":
		unsealer = CubbyUnsealer{
			TempToken: request.Token,
			Path:      request.CubbyPath,
		}
	case "wrapped-token":
		unsealer = WrappedTokenUnsealer{
			TempToken: request.Token,
		}
	default:
		c.JSON(400, struct {
			Status string `json:"status"`
			Ok     bool   `json:"ok"`
			Error  string `json:"error"`
		}{string(state.Status), false, errUnknownAuthMethod.Error()})
		return
	}

	if err := unseal(unsealer); err == nil {
		c.JSON(200, struct {
			Status string `json:"status"`
			Ok     bool   `json:"ok"`
		}{string(state.Status), true})
	} else if err == errAlreadyUnsealed {
		c.JSON(200, struct {
			Status string `json:"status"`
			Ok     bool   `json:"ok"`
			Error  string `json:"error"`
		}{string(state.Status), true, err.Error()})
	} else {
		c.JSON(403, struct {
			Status string `json:"status"`
			Ok     bool   `json:"ok"`
			Error  string `json:"error"`
		}{string(state.Status), false, err.Error()})
	}

}

func Seal(c *gin.Context) {
	seal()
	c.JSON(200, struct {
		Status string `json:"status"`
		Ok     bool   `json:"ok"`
	}{string(state.Status), true})
}

func ReloadPolicies(c *gin.Context) {
	state.RLock()
	status := state.Status
	token := state.Token
	state.RUnlock()

	if status == StatusSealed {
		c.JSON(503, struct {
			Status string `json:"status"`
			Ok     bool   `json:"ok"`
			Error  string `json:"error"`
		}{string(state.Status), false, "Gatekeeper is sealed."})
		return
	}

	state.Lock()
	if err := activePolicies.Load(token); err == nil {
		state.Unlock()
		c.JSON(200, struct {
			Status string `json:"status"`
			Ok     bool   `json:"ok"`
		}{string(state.Status), true})
	} else {
		state.Unlock()
		c.JSON(500, struct {
			Status string `json:"status"`
			Ok     bool   `json:"ok"`
			Error  string `json:"error"`
		}{string(state.Status), false, err.Error()})
	}
}
