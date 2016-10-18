package main

import (
	"encoding/json"
	"errors"
	"github.com/franela/goreq"
	"github.com/gin-gonic/gin"
	"log"
	"strconv"
	"sync/atomic"
	"time"
)

var errTaskNotFresh = errors.New("This task has been running too long to request a token.")
var errAlreadyGivenKey = errors.New("This task has already been given a token.")
var usedTaskIds = NewTtlSet()

func createToken(token string, opts interface{}) (string, error) {
	r, err := VaultRequest{goreq.Request{
		Uri:             vaultPath("/v1/auth/token/create", ""),
		Method:          "POST",
		Body:            opts,
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", token)}.Do()
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

func createWrappedToken(token string, opts interface{}, wrapTTL time.Duration) (string, error) {
	wrapTTLSeconds := strconv.Itoa(int(wrapTTL.Seconds()))

	r, err := VaultRequest{
		goreq.Request{
			Uri:             vaultPath("/v1/auth/token/create", ""),
			Method:          "POST",
			Body:            opts,
			MaxRedirects:    10,
			RedirectHeaders: true,
		}.WithHeader("X-Vault-Token", token).WithHeader("X-Vault-Wrap-TTL", wrapTTLSeconds),
	}.Do()

	if err != nil {
		return "", err
	}
	defer r.Body.Close()

	if r.StatusCode != 200 {
		var e vaultError
		e.Code = r.StatusCode
		if err := r.Body.FromJsonTo(&e); err == nil {
			return "", e
		} else {
			e.Errors = []string{"communication error."}
			return "", e
		}
	}

	t := &vaultTokenResp{}
	if err := r.Body.FromJsonTo(t); err != nil {
		return "", err
	}

	if t.WrapInfo.Token == "" {
		return "", errors.New("Request for wrapped token did not return wrapped response")
	}

	return t.WrapInfo.Token, nil
}

func createTokenPair(token string, p *policy) (string, error) {
	pol := p.Policies
	if len(pol) == 0 { // explicitly set the policy, else the token will inherit ours
		pol = []string{"default"}
	}

	permTokenOpts := struct {
		Ttl       string            `json:"ttl,omitempty"`
		Policies  []string          `json:"policies"`
		Meta      map[string]string `json:"meta,omitempty"`
		NumUses   int               `json:"num_uses"`
		NoParent  bool              `json:"no_parent"`
		Renewable bool              `json:"renewable"`
	}{time.Duration(time.Duration(p.Ttl) * time.Second).String(), pol, p.Meta, p.NumUses, true, true}

	return createWrappedToken(token, permTokenOpts, 10*time.Minute)
}

func Provide(c *gin.Context) {
	requestStartTime := time.Now()
	state.RLock()
	status := state.Status
	token := state.Token
	state.RUnlock()

	remoteIp := c.Request.RemoteAddr

	atomic.AddInt32(&state.Stats.Requests, 1)

	if status == StatusSealed {
		log.Printf("Rejected token request from %s. Reason: sealed.", remoteIp)
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
			log.Printf("Rejected token request from %s (Task Id: %s). Reason: %v", remoteIp, reqParams.TaskId, errAlreadyGivenKey)
			atomic.AddInt32(&state.Stats.Denied, 1)
			c.JSON(403, struct {
				Status string `json:"status"`
				Ok     bool   `json:"ok"`
				Error  string `json:"error"`
			}{string(state.Status), false, errAlreadyGivenKey.Error()})
			return
		}
		/*
			The task can start, but the task's framework may have not reported
			that it is RUNNING back to mesos. In this case, the task will still
			be STAGING and have a statuses length of 0.

			This is a network race, so we just sleep and try again.
		*/
		gMT := func(taskId string) (mesosTask, error) {
			task, err := getMesosTask(taskId)
			for i := time.Duration(0); i < 3 && err == nil && len(task.Statuses) == 0; i++ {
				time.Sleep((500 + 250*i) * time.Millisecond)
				task, err = getMesosTask(taskId)
			}
			return task, err
		}

		// TODO: Remove this when we can incorporate Mesos in testing environment
		if reqParams.TaskId == state.testingTaskId && state.testingTaskId != "" {
			gMT = func(taskId string) (mesosTask, error) {
				return mesosTask{
					Statuses: []struct {
						State     string  `json:"state"`
						Timestamp float64 `json:"timestamp"`
					}{{"RUNNING", float64(time.Now().UnixNano()) / float64(1000000000)}},
					Id:   reqParams.TaskId,
					Name: "Test",
				}, nil
			}
		}
		if task, err := gMT(reqParams.TaskId); err == nil {
			if len(task.Statuses) == 0 {
				log.Printf("Rejected token request from %s (Task Id: %s). Reason: %v (no status)", remoteIp, reqParams.TaskId, errTaskNotFresh)
				atomic.AddInt32(&state.Stats.Denied, 1)
				c.JSON(403, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Error  string `json:"error"`
				}{string(state.Status), false, errTaskNotFresh.Error()})
				return
			}
			// https://github.com/apache/mesos/blob/a61074586d778d432ba991701c9c4de9459db897/src/webui/master/static/js/controllers.js#L148
			startTime := time.Unix(0, int64(task.Statuses[0].Timestamp*1000000000))
			if time.Now().Sub(startTime) > config.MaxTaskLife {
				log.Printf("Rejected token request from %s (Task Id: %s). Reason: %v (no status)", remoteIp, reqParams.TaskId, errTaskNotFresh)
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
				log.Printf("Provided token pair for %s in %v. (Task Id: %s) (Task Name: %s). Policies: %v", remoteIp, time.Now().Sub(requestStartTime), reqParams.TaskId, task.Name, policy.Policies)
				atomic.AddInt32(&state.Stats.Successful, 1)
				usedTaskIds.Put(reqParams.TaskId, config.MaxTaskLife+1*time.Minute)
				c.JSON(200, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Token  string `json:"token"`
				}{string(state.Status), true, tempToken})
			} else {
				log.Printf("Failed to create token pair for %s (Task Id: %s). Reason: %v", remoteIp, reqParams.TaskId, errTaskNotFresh)
				atomic.AddInt32(&state.Stats.Denied, 1)
				c.JSON(500, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Error  string `json:"error"`
				}{string(state.Status), false, err.Error()})
			}
		} else if err == errNoSuchTask {
			log.Printf("Rejected token request from %s (Task Id: %s). Reason: %v", remoteIp, reqParams.TaskId, errNoSuchTask)
			atomic.AddInt32(&state.Stats.Denied, 1)
			c.JSON(403, struct {
				Status string `json:"status"`
				Ok     bool   `json:"ok"`
				Error  string `json:"error"`
			}{string(state.Status), false, err.Error()})
		} else {
			log.Printf("Failed to retrieve task information for %s (Task Id: %s). Reason: %v", remoteIp, reqParams.TaskId, err)
			atomic.AddInt32(&state.Stats.Denied, 1)
			c.JSON(500, struct {
				Status string `json:"status"`
				Ok     bool   `json:"ok"`
				Error  string `json:"error"`
			}{string(state.Status), false, err.Error()})
		}
	} else {
		log.Printf("Rejected token request from %s. Reason: %v", remoteIp, err)
		atomic.AddInt32(&state.Stats.Denied, 1)
		c.JSON(400, struct {
			Status string `json:"status"`
			Ok     bool   `json:"ok"`
			Error  string `json:"error"`
		}{string(state.Status), false, err.Error()})
	}
}
