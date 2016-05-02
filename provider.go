package main

import (
	"encoding/json"
	"errors"
	"github.com/franela/goreq"
	"github.com/gin-gonic/gin"
	"time"
)

var errTaskNotFresh = errors.New("This task has been running too long to request a token.")

func createToken(token string, opts interface{}) (string, error) {
	r, err := goreq.Request{
		Uri:    vaultPath("/v1/auth/token/create-orphan", ""),
		Method: "POST",
		Body:   opts,
	}.WithHeader("X-Vault-Token", token).Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			var t vaultTokenResp
			if err := r.Body.FromJsonTo(&t); err == nil {
				return t.Auth.ClientToken, nil
			} else {
				return "", err
			}
		default:
			var e vaultError
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return "", e
			} else {
				e.Errors = []string{"communication error."}
				return "", e
			}
		}
	} else {
		return "", err
	}
}

func createTokenPair(token string, p *policy) (string, error) {
	tempTokenOpts := struct {
		Ttl     string `json:"ttl"`
		NumUses int    `json:"num_uses"`
	}{"10m", 2}
	permTokenOpts := struct {
		Ttl      string            `json:"ttl,omitempty"`
		Policies []string          `json:"policies"`
		Meta     map[string]string `json:"meta,omitempty"`
		NumUses  int               `json:"num_uses"`
	}{time.Duration(time.Duration(p.Ttl) * time.Second).String(), p.Policies, p.Meta, p.NumUses}

	if tempToken, err := createToken(token, tempTokenOpts); err == nil {
		if permToken, err := createToken(token, permTokenOpts); err == nil {
			r, err := goreq.Request{
				Uri:    vaultPath("/v1/cubbyhole/vault-token", ""),
				Method: "POST",
				Body: struct {
					Token string `json:"token"`
				}{permToken},
			}.WithHeader("X-Vault-Token", tempToken).Do()
			if err == nil {
				defer r.Body.Close()
				switch r.StatusCode {
				case 204:
					return tempToken, nil
				default:
					var e vaultError
					e.Code = r.StatusCode
					if err := r.Body.FromJsonTo(&e); err == nil {
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
			return "", err
		}
	} else {
		return "", err
	}
}

func Provide(c *gin.Context) {
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

	var reqParams struct {
		TaskId string `json:"task_id"`
	}
	decoder := json.NewDecoder(c.Request.Body)
	if err := decoder.Decode(&reqParams); err == nil {
		if task, err := getMesosTask(reqParams.TaskId); err == nil {
			startTime := time.Unix(0, int64(task.Statuses[len(task.Statuses)-1].Timestamp*1000000000))
			if time.Now().Sub(startTime) > config.MaxTaskLife {
				c.JSON(403, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Error  string `json:"error"`
				}{string(state.Status), false, errTaskNotFresh.Error()})
				return
			}
			state.RLock()
			policy := activePolicies.Get(task.Name)
			state.RUnlock()
			if tempToken, err := createTokenPair(token, policy); err == nil {
				c.JSON(200, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Token  string `json:"token"`
				}{string(state.Status), true, tempToken})
			} else {
				c.JSON(500, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Error  string `json:"error"`
				}{string(state.Status), false, err.Error()})
			}
		} else if err == errNoSuchTask {
			c.JSON(403, struct {
				Status string `json:"status"`
				Ok     bool   `json:"ok"`
				Error  string `json:"error"`
			}{string(state.Status), false, err.Error()})
		} else {
			c.JSON(500, struct {
				Status string `json:"status"`
				Ok     bool   `json:"ok"`
				Error  string `json:"error"`
			}{string(state.Status), false, err.Error()})
		}
	} else {
		c.JSON(400, struct {
			Status string `json:"status"`
			Ok     bool   `json:"ok"`
			Error  string `json:"error"`
		}{string(state.Status), false, err.Error()})
	}
}
