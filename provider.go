package main

import (
	"encoding/json"
	"errors"
	"github.com/franela/goreq"
	"github.com/gin-gonic/gin"
	"sync/atomic"
	"time"
)

var errTaskNotFresh = errors.New("This task has been running too long to request a token.")
var errAlreadyGivenKey = errors.New("This task has already been given a token.")
var usedTaskIds = NewTtlSet()

func createToken(token string, opts interface{}) (string, error) {
	r, err := goreq.Request{
		Uri:    vaultPath("/v1/auth/token/create", ""),
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
		Ttl      string   `json:"ttl"`
		NumUses  int      `json:"num_uses"`
		Policies []string `json:"policies"`
		NoParent bool     `json:"no_parent"`
	}{"10m", 2, []string{"default"}, true}
	pol := p.Policies
	if len(pol) == 0 { // explicitly set the policy, else the token will inherit ours
		pol = []string{"default"}
	}
	permTokenOpts := struct {
		Ttl      string            `json:"ttl,omitempty"`
		Policies []string          `json:"policies"`
		Meta     map[string]string `json:"meta,omitempty"`
		NumUses  int               `json:"num_uses"`
		NoParent bool              `json:"no_parent"`
	}{time.Duration(time.Duration(p.Ttl) * time.Second).String(), pol, p.Meta, p.NumUses, true}

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

	atomic.AddInt32(&state.Stats.Requests, 1)

	if status == StatusSealed {
		atomic.AddInt32(&state.Stats.Denied, 1)
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
		if usedTaskIds.Has(reqParams.TaskId) {
			atomic.AddInt32(&state.Stats.Denied, 1)
			c.JSON(403, struct {
				Status string `json:"status"`
				Ok     bool   `json:"ok"`
				Error  string `json:"error"`
			}{string(state.Status), false, errAlreadyGivenKey.Error()})
			return
		}
		if task, err := getMesosTask(reqParams.TaskId); err == nil {
			if len(task.Statuses) == 0 {
				atomic.AddInt32(&state.Stats.Denied, 1)
				c.JSON(403, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Error  string `json:"error"`
				}{string(state.Status), false, errTaskNotFresh.Error()})
				return
			}
			startTime := time.Unix(0, int64(task.Statuses[len(task.Statuses)-1].Timestamp*1000000000))
			if time.Now().Sub(startTime) > config.MaxTaskLife {
				atomic.AddInt32(&state.Stats.Denied, 1)
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
				atomic.AddInt32(&state.Stats.Successful, 1)
				usedTaskIds.Put(reqParams.TaskId, config.MaxTaskLife+1*time.Minute)
				c.JSON(200, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Token  string `json:"token"`
				}{string(state.Status), true, tempToken})
			} else {
				atomic.AddInt32(&state.Stats.Denied, 1)
				c.JSON(500, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Error  string `json:"error"`
				}{string(state.Status), false, err.Error()})
			}
		} else if err == errNoSuchTask {
			atomic.AddInt32(&state.Stats.Denied, 1)
			c.JSON(403, struct {
				Status string `json:"status"`
				Ok     bool   `json:"ok"`
				Error  string `json:"error"`
			}{string(state.Status), false, err.Error()})
		} else {
			atomic.AddInt32(&state.Stats.Denied, 1)
			c.JSON(500, struct {
				Status string `json:"status"`
				Ok     bool   `json:"ok"`
				Error  string `json:"error"`
			}{string(state.Status), false, err.Error()})
		}
	} else {
		atomic.AddInt32(&state.Stats.Denied, 1)
		c.JSON(400, struct {
			Status string `json:"status"`
			Ok     bool   `json:"ok"`
			Error  string `json:"error"`
		}{string(state.Status), false, err.Error()})
	}
}
