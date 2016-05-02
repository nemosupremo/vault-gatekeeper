package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/samuel/go-zookeeper/zk"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type mesosMaster struct {
	Address struct {
		Hostname string `json:"hostname"`
		Ip       string `json:"ip"`
		Port     int    `json:"port"`
	} `json:"address"`
	Hostname string `json:"hostname"`
	Id       string `json:"id"`
	Ip       int64  `json:"ip"`
	Pid      string `json:"pid"`
	Port     int    `json:"port"`
	Version  string `json:"version"`
}

type mesosTask struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	State     string `json:"state"`
	SlaveId   string `json:"slave_id"`
	Resources struct {
		Cpus  float64 `json:"cpus"`
		Disk  float64 `json:"disk"`
		Mem   float64 `json:"mem"`
		Ports string  `json:"ports"`
	} `json:"resources"`
	Statuses []struct {
		State     string  `json:"state"`
		Timestamp float64 `json:"timestamp"`
	} `json:"statuses"`
}

type mesosState struct {
	GitSha     string `json:"git_sha"`
	GitTag     string `json:"git_tag"`
	Leader     string `json:"leader"`
	Pid        string `json:"pid"`
	Frameworks []struct {
		Id     string      `json:"id"`
		Name   string      `json:"name"`
		Active bool        `json:"active"`
		Tasks  []mesosTask `json:"tasks"`
	} `json:"frameworks"`
}

var errMesosNoPath = errors.New("No path specified for mesos zk lookup.")
var errMesosParseError = errors.New("Error parsing mesos master data in zk.")
var errMesosNoMaster = errors.New("Error finding mesos master.")
var errUnknownScheme = errors.New("Unknown mesos scheme.")
var errMesosUnreachable = errors.New("No reachable mesos masters.")
var errNoSuchTask = errors.New("No such task.")

func getMesosMaster() ([]string, error) {
	var masterHosts []string

	if path, err := url.Parse(config.Mesos); err == nil {
		switch path.Scheme {
		case "zk":
			if path.Path == "" || path.Path == "/" {
				return nil, errMesosNoPath
			}
			zookeeperPath := path.Path
			if zookeeperPath[0] != '/' {
				zookeeperPath = "/" + zookeeperPath
			}
			if zoo, _, err := zk.Connect(strings.Split(path.Host, ","), 10*time.Second); err == nil {
				defer zoo.Close()
				if children, _, err := zoo.Children(zookeeperPath); err == nil {
					sort.Strings(children)
					for _, child := range children {
						if strings.HasPrefix(child, "json.info_") {
							if data, _, err := zoo.Get(zookeeperPath + "/" + child); err == nil {
								var masterInfo mesosMaster
								if err := json.Unmarshal(data, &masterInfo); err == nil {
									masterHosts = []string{fmt.Sprintf("%s:%d", masterInfo.Address.Hostname, masterInfo.Address.Port)}
									break
								} else {
									return nil, errMesosParseError

								}
							}
						}
					}
				} else {
					return nil, errMesosNoMaster
				}
			}
		case "http", "https":
			masterHosts = strings.Split(path.Host, ",")
		default:
			return nil, errUnknownScheme
		}
	} else {
		masterHosts = strings.Split(config.Mesos, ",")
	}

	if len(masterHosts) == 0 {
		return nil, errMesosUnreachable
	}
	return masterHosts, nil
}

func getMesosTask(taskId string) (mesosTask, error) {
	var state mesosState
	var masterErr error
	if masterHosts, err := getMesosMaster(); err == nil {
		for _, host := range masterHosts {
			if resp, err := http.Get("http://" + host + "/state.json"); err == nil {
				defer resp.Body.Close()
				if err := json.NewDecoder(resp.Body).Decode(&state); err == nil {
					if state.Pid == state.Leader {
						masterErr = nil
						break
					}
				} else {
					masterErr = err
				}
			} else {
				masterErr = err
			}
		}
		if masterErr != nil {
			return mesosTask{}, masterErr
		}
		if state.Pid != state.Leader {
			return mesosTask{}, errMesosUnreachable
		}

		for _, framework := range state.Frameworks {
			for _, task := range framework.Tasks {
				if task.Id == taskId {
					return task, nil
				}
			}

		}
		return mesosTask{}, errNoSuchTask
	} else {
		return mesosTask{}, err
	}
}
