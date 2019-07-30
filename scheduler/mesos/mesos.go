package mesos

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nemosupremo/vault-gatekeeper/scheduler"

	"github.com/mesos/mesos-go/api/v0/upid"
	"github.com/samuel/go-zookeeper/zk"
	"github.com/sirupsen/logrus"
)

type defaultLogger struct{}

func (d defaultLogger) Printf(s string, a ...interface{}) {
	logrus.Debugf(s, a...)
}

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
	Container struct {
		Type   string `json:"type"`
		Docker struct {
			Image string `json:"image"`
		} `json:"docker"`
	} `json:"container"`
}

type mesosState struct {
	GitSha string `json:"git_sha"`
	GitTag string `json:"git_tag"`
	Leader string `json:"leader"`
	Pid    string `json:"pid"`
	Slaves []struct {
		Id  string `json:"id"`
		PID string `json:"pid"`
	} `json:"slaves"`
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

type mesosScheduler struct {
	Master string
}

type task struct {
	id        string
	name      string
	group     string
	image     string
	ip        net.IP
	startTime time.Time
}

func (t task) Id() string {
	return t.id
}

func (t task) Group() string {
	return t.group
}

func (t task) Image() string {
	return t.image
}

func (t task) Name() string {
	return t.name
}

func (t task) IP() net.IP {
	return t.ip
}

func (t task) StartTime() time.Time {
	return t.startTime
}

func NewMesosScheduler(master string) (scheduler.Scheduler, error) {
	m := &mesosScheduler{master}
	if _, _, err := m.getMesosMaster(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *mesosScheduler) LookupTask(taskId string) (scheduler.Task, error) {
	mesosTask, framework, slaveHost, err := m.getMesosTask(taskId)
	for i := time.Duration(0); i < 3 && err == nil && len(mesosTask.Statuses) == 0; i++ {
		time.Sleep((500 + 250*i) * time.Millisecond)
		mesosTask, framework, slaveHost, err = m.getMesosTask(taskId)
	}
	runningTime := time.Unix(0, 0)
	if len(mesosTask.Statuses) > 0 {
		// https://github.com/apache/mesos/blob/a61074586d778d432ba991701c9c4de9459db897/src/webui/master/static/js/controllers.js#L148
		runningTime = time.Unix(0, int64(mesosTask.Statuses[0].Timestamp*1000000000))
	}

	var ip net.IP
	if err == nil {
		if ips, err := net.LookupIP(slaveHost); err == nil {
			ip = ips[0]
		}
	}

	return &task{
		id:        mesosTask.Id,
		name:      mesosTask.Name,
		image:     mesosTask.Container.Docker.Image,
		group:     framework,
		startTime: runningTime,
		ip:        ip,
	}, err
}

func (m *mesosScheduler) getMesosMaster() ([]string, string, error) {
	var masterHosts []string
	protocol := "http"
	if path, err := url.Parse(m.Master); err == nil {
		switch path.Scheme {
		case "zks":
			protocol = "https"
			fallthrough
		case "zk":
			if path.Path == "" || path.Path == "/" {
				return nil, protocol, errMesosNoPath
			}
			zookeeperPath := path.Path
			if zookeeperPath[0] != '/' {
				zookeeperPath = "/" + zookeeperPath
			}

			if zoo, _, err := zk.Connect(zk.FormatServers(strings.Split(path.Host, ",")), 10*time.Second, zk.WithLogger(&defaultLogger{})); err == nil {
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
									return nil, protocol, errMesosParseError

								}
							}
						}
					}
				} else {
					return nil, protocol, errMesosNoMaster
				}
			}
		case "https":
			protocol = "https"
			fallthrough
		case "http":
			masterHosts = strings.Split(path.Host, ",")
		default:
			return nil, protocol, errUnknownScheme
		}
	} else {
		masterHosts = strings.Split(m.Master, ",")
	}

	if len(masterHosts) == 0 {
		return nil, protocol, errMesosUnreachable
	}
	return masterHosts, protocol, nil
}

func (m *mesosScheduler) getMesosTask(taskId string) (mesosTask, string, string, error) {
	var state mesosState
	var masterErr error
	if masterHosts, protocol, err := m.getMesosMaster(); err == nil {
		for _, host := range masterHosts {
			if resp, err := http.Get(protocol + "://" + host + "/state"); err == nil {
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
			return mesosTask{}, "", "", masterErr
		}
		if state.Pid != state.Leader {
			return mesosTask{}, "", "", errMesosUnreachable
		}

		slaves := make(map[string]string)
		for _, slave := range state.Slaves {
			slaves[slave.Id] = slave.PID
		}

		for _, framework := range state.Frameworks {
			for _, task := range framework.Tasks {
				if task.Id == taskId {
					slaveHost := ""
					if slavePid, ok := slaves[task.SlaveId]; ok {
						if pid, err := upid.Parse(slavePid); err == nil {
							slaveHost = pid.Host
						} else {
							logrus.Warnf("Mesos: Failed to parse PID %v.", slavePid)
						}
					} else {
						logrus.Warnf("Mesos: Task ID %v was running on Slave %v, but no information about that slave was found.", task.Id, task.SlaveId)
					}
					return task, framework.Name, slaveHost, nil
				}
			}
		}
		return mesosTask{}, "", "", scheduler.ErrTaskNotFound
	} else {
		return mesosTask{}, "", "", err
	}
}
