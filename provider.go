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

type RunningTask struct {
	Id        string
	Name      string
	StartTime time.Time
}

func (t *RunningTask) Valid() bool {
	return t != nil && t.StartTime.IsZero()
}

type Provider func(string) (RunningTask, error)

var errTaskNotFresh = errors.New("This task has been running too long to request a token.")
var errTaskEmptyStatuses = errors.New("This task does not have any statuses.")
var errAlreadyGivenKey = errors.New("This task has already been given a token.")
var errMaxTokensGiven = errors.New("Maximum number of tokens given to this task.")
var errNoSupportedProvider = errors.New("No supported provider has been configured.")
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
		/*
			The task can start, but the task's framework may have not reported
			that it is RUNNING back to mesos. In this case, the task will still
			be STAGING and have a statuses length of 0.

			This is a network race, so we just sleep and try again.
		*/
		gMT := getProvider()

		if task, err := gMT(reqParams.TaskId); err == nil {
			if task.Valid() {
				log.Printf("Rejected token request from %s (Task Id: %s). Reason: %v (no status)", remoteIp, task.TaskId, errTaskEmptyStatuses)
				atomic.AddInt32(&state.Stats.Denied, 1)
				c.JSON(403, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Error  string `json:"error"`
				}{string(state.Status), false, errTaskEmptyStatuses.Error()})
				return
			}
			// https://github.com/apache/mesos/blob/a61074586d778d432ba991701c9c4de9459db897/src/webui/master/static/js/controllers.js#L148
			startTime := task.StartTime
			taskLife := time.Now().Sub(startTime)
			if taskLife > config.MaxTaskLife {
				log.Printf("Rejected token request from %s (Task Id: %s). Reason: %v (no status) Task Life: %s", remoteIp, task.TaskId, errTaskNotFresh, taskLife)
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

			if !policy.MultiFetch && usedTaskIds.Has(task.TaskId) {
				log.Printf("Rejected token request from %s (Task Id: %s). Reason: %v", remoteIp, task.TaskId, errAlreadyGivenKey)
				atomic.AddInt32(&state.Stats.Denied, 1)
				c.JSON(403, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Error  string `json:"error"`
				}{string(state.Status), false, errAlreadyGivenKey.Error()})
				return
			}
			if policy.MultiFetch && usedTaskIds.UsageCount(task.TaskId) >= policy.MultiFetchLimit {
				log.Printf("Rejected token request from %s (Task Id: %s). Reason: %v Limit: %v", remoteIp, task.TaskId, errMaxTokensGiven, policy.MultiFetchLimit)
				atomic.AddInt32(&state.Stats.Denied, 1)
				c.JSON(403, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Error  string `json:"error"`
				}{string(state.Status), false, errMaxTokensGiven.Error()})
				return
			}
			if tempToken, err := createTokenPair(token, policy); err == nil {
				log.Printf("Provided token pair for %s in %v. (Task Id: %s) (Task Name: %s). Policies: %v", remoteIp, time.Now().Sub(requestStartTime), task.TaskId, task.Name, policy.Policies)
				atomic.AddInt32(&state.Stats.Successful, 1)
				usedTaskIds.Put(task.TaskId, config.MaxTaskLife+1*time.Minute)
				c.JSON(200, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Token  string `json:"token"`
				}{string(state.Status), true, tempToken})
			} else {
				log.Printf("Failed to create token pair for %s (Task Id: %s). Error: %v", remoteIp, task.TaskId, err)
				atomic.AddInt32(&state.Stats.Denied, 1)
				c.JSON(500, struct {
					Status string `json:"status"`
					Ok     bool   `json:"ok"`
					Error  string `json:"error"`
				}{string(state.Status), false, err.Error()})
			}
		} else if err == errNoSuchTask {
			log.Printf("Rejected token request from %s (Task Id: %s). Reason: %v", remoteIp, task.TaskId, errNoSuchTask)
			atomic.AddInt32(&state.Stats.Denied, 1)
			c.JSON(403, struct {
				Status string `json:"status"`
				Ok     bool   `json:"ok"`
				Error  string `json:"error"`
			}{string(state.Status), false, err.Error()})
		} else {
			log.Printf("Failed to retrieve task information for %s (Task Id: %s). Reason: %v", remoteIp, task.TaskId, err)
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

func getProvider() Provider {
	if config.Provider == "mesos" {
		return mesosProvider
	}

	if config.Provider == "ecs" {
		return ecsProvider
	}

	if config.Provider == "test" { //|| (reqParams.TaskId == state.testingTaskId && state.testingTaskId != "") {
		return testProvider
	}

	if config.Provider == "mesos_test" {
		return mesosTestProvider
	}

	return func(taskId string) (RunningTask, error) {
		return RunningTask{}, errNoSupportedProvider
	}
}
