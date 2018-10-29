package dcosee_mesos

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/spf13/viper"

	"vault-gatekeeper/scheduler"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mesos/mesos-go/api/v0/upid"
	"github.com/samuel/go-zookeeper/zk"
	log "github.com/sirupsen/logrus"
)

const defaultLoginExp time.Duration = time.Minute * 5

type defaultLogger struct{}

func (d defaultLogger) Printf(s string, a ...interface{}) {
	log.Debugf(s, a...)
}

type mesosMaster struct {
	Address struct {
		Hostname string `json:"hostname"`
		IP       string `json:"ip"`
		Port     int    `json:"port"`
	} `json:"address"`
	Hostname string `json:"hostname"`
	ID       string `json:"id"`
	IP       int64  `json:"ip"`
	Pid      string `json:"pid"`
	Port     int    `json:"port"`
	Version  string `json:"version"`
}

type mesosFramework struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type mesosTask struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	State       string `json:"state"`
	SlaveID     string `json:"slave_id"`
	FrameworkID string `json:"framework_id"`
	Resources   struct {
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

type mesosSlave struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	PID      string `json:"pid"`
}

type mesosSlaves struct {
	Slaves []*mesosSlave `json:"slaves"`
}

type mesosTasks struct {
	Tasks []*mesosTask `json:"tasks"`
}

type mesosFrameworks struct {
	Frameworks []*mesosFramework `json:"frameworks"`
}

var errMesosNoPath = errors.New("No path specified for mesos zk lookup.")
var errMesosParseError = errors.New("Error parsing mesos master data in zk.")
var errMesosNoMaster = errors.New("Error finding mesos master.")
var errUnknownScheme = errors.New("Unknown mesos scheme.")
var errZKNotSupportedScheme = errors.New("zk or zks is not supported for the enterprise edition of DCOS.  Please add the list of master nodes directly.")
var errMesosUnreachable = errors.New("No reachable mesos masters.")

type mesosScheduler struct {
	master             string
	uid                string
	privateKey         *rsa.PrivateKey
	authorizationToken string
	expiration         time.Time
	client             *http.Client
}

//Returned Task information from the lookup
type task struct {
	id        string
	name      string
	group     string
	image     string
	ip        net.IP
	startTime time.Time
}

// Return the Task ID
func (t task) Id() string {
	return t.id
}

// Return the Task Group
func (t task) Group() string {
	return t.group
}

// Return the Task Image
func (t task) Image() string {
	return t.image
}

// Return the Task Name
func (t task) Name() string {
	return t.name
}

// Return the Task IP
func (t task) IP() net.IP {
	return t.ip
}

//Return the Task Start Time
func (t task) StartTime() time.Time {
	return t.startTime
}

//NewMesosScheduler creates the object for talking to mesos.  In this case it
// will create the object to talk to DCOS EE Mesos which needs some authentication
// pieces setup
func NewMesosScheduler(master string, uid string, privateKeyFile io.Reader) (scheduler.Scheduler, error) {
	//Create the object
	m := &mesosScheduler{
		master: master,
		uid:    uid,
	}

	//Parse and validate the private key
	if err := m.parsePrivateKey(privateKeyFile); err != nil {
		return nil, err
	}

	//Build the transport
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	//If requested ignore the TLS verify
	if viper.GetBool("mesos-skipverify") {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		} else {
			tr.TLSClientConfig.InsecureSkipVerify = true
		}
	}
	client := http.DefaultClient
	client.Transport = tr
	m.client = client

	//Check to see if you can communicate with the Mesos Master
	if _, _, err := m.getMesosMaster(); err != nil {
		return nil, err
	}

	//Create initial authorization token
	if err := m.createAuthorizationToken(); err != nil {
		return nil, err
	}

	return m, nil
}

//Parse the private Key for the JWT
func (m *mesosScheduler) parsePrivateKey(privateKeyFile io.Reader) error {
	//Read the Data from the private key file
	data, err := ioutil.ReadAll(privateKeyFile)
	if err != nil {
		return err
	}

	//Parse the data in to the Private Key object
	//If we need a password object for this we will have to use a different function
	pk, err := jwt.ParseRSAPrivateKeyFromPEM(data)
	if err != nil {
		return err
	}

	//Validate the private key
	if err := pk.Validate(); err != nil {
		return err
	}

	//Set the key in the scheduler object
	m.privateKey = pk
	return nil
}

//Create the DCOS login token based on the private key and uid
func (m *mesosScheduler) createLoginToken() ([]byte, error) {
	// create a signer for rsa 256
	sm := jwt.GetSigningMethod("RS256")
	mc := jwt.MapClaims{}
	t := jwt.NewWithClaims(sm, mc)

	// set our claims
	mc["uid"] = m.uid

	// set the expire time
	// see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4.1.4
	mc["exp"] = time.Now().Add(defaultLoginExp).Unix()

	tokenString, err := t.SignedString(m.privateKey)
	if err != nil {
		log.Errorf("Token Signing error: %v\n", err)
		return nil, err
	}

	log.Debugf("Login Token: %s\n", tokenString)

	return []byte(tokenString), nil
}

type loginStruct struct {
	UID   string `json:"uid"`
	Exp   uint   `json:"exp"`
	Token string `json:"token"`
}

func (m *mesosScheduler) createAuthorizationToken() error {
	dur := m.expiration.Sub(time.Now())
	if len(m.authorizationToken) > 0 && dur.Hours() > 1 {
		return nil
	}

	loginToken, err := m.createLoginToken()
	if err != nil {
		return err
	}

	if masterHosts, protocol, err := m.getMesosMaster(); err == nil {
		for _, host := range masterHosts {
			hostport := strings.Split(host, ":")

			login := &loginStruct{
				UID:   m.uid,
				Exp:   0,
				Token: string(loginToken),
			}

			data, _ := json.Marshal(login)

			log.Debugf("Login Data: %s\n", data)

			bodyRdr := bytes.NewReader(data)
			req, _ := http.NewRequest("POST", protocol+"://"+hostport[0]+"/acs/api/v1/auth/login", bodyRdr)
			req.Header.Add("content-type", "application/json")

			resp, err := m.client.Do(req)
			if err == nil && resp.StatusCode == 200 {
				defer resp.Body.Close()

				jsonMap := make(map[string]string)

				derr := json.NewDecoder(resp.Body).Decode(&jsonMap)
				if derr != nil {
					return derr
				}

				log.Debugf("Authorization Response: %+v\n", jsonMap)
				token, ok := jsonMap["token"]
				if ok {
					m.authorizationToken = token
					exp := time.Duration(login.Exp) * time.Second
					if login.Exp == 0 {
						exp = time.Duration(5*24) * time.Hour
					}
					m.expiration = time.Now().Add(exp)
				}

			} else if err != nil {
				return err
			} else {
				defer resp.Body.Close()
				msg, _ := ioutil.ReadAll(resp.Body)
				return fmt.Errorf("Error Code: %d  Message: %s", resp.StatusCode, msg)
			}
		}
	} else {
		return err
	}

	return nil
}

//LookupTask  takes the provided taskId and looks up the task in Mesos
// to verify the task in fact does exist
func (m *mesosScheduler) LookupTask(taskID string) (scheduler.Task, error) {

	//Try to fetch the Mesos Task ID Information  Keep trying for a short period.
	mesosTask, slaveHost, framework, err := m.getMesosTask(taskID)
	for i := time.Duration(0); i < 3 && err == nil && len(mesosTask.Statuses) == 0; i++ {
		time.Sleep((500 + 250*i) * time.Millisecond)
		mesosTask, slaveHost, framework, err = m.getMesosTask(taskID)
	}

	//See how long the task has been running
	runningTime := time.Unix(0, 0)
	if len(mesosTask.Statuses) > 0 {
		// https://github.com/apache/mesos/blob/a61074586d778d432ba991701c9c4de9459db897/src/webui/master/static/js/controllers.js#L148
		runningTime = time.Unix(0, int64(mesosTask.Statuses[0].Timestamp*1000000000))
	}

	//Find the task IP by looking up the slave it is running on
	var ip net.IP
	if err == nil {
		if ips, err := net.LookupIP(slaveHost); err == nil {
			ip = ips[0]
		}
	}

	log.Debugf("Return Looked Up Value as %s@%s:%s\n", ip, framework, mesosTask.Name)

	return &task{
		id:        mesosTask.ID,
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
	if path, err := url.Parse(m.master); err == nil {
		switch path.Scheme {
		case "zks":
			protocol = "https"
			fallthrough
		case "zk":
			masterHosts, err = m.parseZK(path)
			if err != nil {
				return nil, protocol, err
			}
			// return nil, protocol, errZKNotSupportedScheme
		case "https":
			protocol = "https"
			fallthrough
		case "http":
			masterHosts = strings.Split(path.Host, ",")
		default:
			return nil, protocol, errUnknownScheme
		}
	} else {
		masterHosts = strings.Split(m.master, ",")
	}

	if len(masterHosts) == 0 {
		return nil, protocol, errMesosUnreachable
	}
	return masterHosts, protocol, nil
}

//parse the zookeeper data to find the master nodes
func (m *mesosScheduler) parseZK(path *url.URL) ([]string, error) {
	//No path provided in url for the root location
	if path.Path == "" || path.Path == "/" {
		return nil, errMesosNoPath
	}

	//Get the path for zookeeper to look into it
	zookeeperPath := path.Path
	if zookeeperPath[0] != '/' {
		zookeeperPath = "/" + zookeeperPath
	}

	//Connect to zookeeper and find the master objects to parse
	var masterHosts []string
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
							return nil, errMesosParseError
						}
					}
				}
			}
		} else {
			return nil, errMesosNoMaster
		}
	}

	return masterHosts, nil
}

func (m *mesosScheduler) getSlaveInfo(slaveId, protocol, host string) (*mesosSlave, error) {
	var slaves mesosSlaves

	log.Debugf("Get Slave information. \n")
	slavesReq, err := http.NewRequest("GET", protocol+"://"+host+"/slaves", nil)
	if err != nil {
		return nil, err
	}

	slavesReq.Header.Add("content-type", "application/json")
	slavesReq.Header.Add("authorization", "token="+m.authorizationToken)
	resp, err := m.client.Do(slavesReq)
	if err == nil && resp != nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		derr := json.NewDecoder(resp.Body).Decode(&slaves)
		if derr != nil {
			return nil, derr
		}
		log.Debugf("Slave Info: %+v\n", slaves)
	} else {
		sc := -1
		if resp != nil {
			sc = resp.StatusCode
		}
		log.Errorf("Error Slave Req.  Error Code: %d  Error: %v\n", sc, err)
		return nil, err
	}

	for _, slave := range slaves.Slaves {
		if slave.ID == slaveId {
			return slave, nil
		}
	}

	return nil, fmt.Errorf("Could not find the slaveId %s in the master.", slaveId)
}

func (m *mesosScheduler) getFrameworkInfo(frameworkId, protocol, host string) (*mesosFramework, error) {
	var frameworks mesosFrameworks

	log.Debugf("Get Framework Info %s\n", frameworkId)
	frameworkReq, err := http.NewRequest("GET", protocol+"://"+host+"/frameworks?framwork_id="+frameworkId, nil)
	if err != nil {
		return nil, err
	}
	frameworkReq.Header.Add("content-type", "application/json")
	frameworkReq.Header.Add("authorization", "token="+m.authorizationToken)

	//Execute the request
	fresp, err := m.client.Do(frameworkReq)
	if err == nil && fresp != nil && fresp.StatusCode == 200 {
		defer fresp.Body.Close()
		derr := json.NewDecoder(fresp.Body).Decode(&frameworks)
		if derr != nil {
			return nil, derr
		}
		log.Debugf("Framework Info: %+v\n", frameworks)
	} else {
		sc := -1
		if fresp != nil {
			sc = fresp.StatusCode
		}

		log.Errorf("Error Task Req.  Error Code: %d  Error: %v\n", sc, err)
		return nil, err
	}

	for _, framework := range frameworks.Frameworks {
		if framework.ID == frameworkId {
			return framework, nil
		}
	}

	return nil, fmt.Errorf("Could not find frameworkId %s in mesos.", frameworkId)
}

func (m *mesosScheduler) getTaskInfo(taskId, protocol, host string) (*mesosTask, error) {
	var tasks mesosTasks

	log.Debugf("Get Task Info %s\n", taskId)
	taskReq, err := http.NewRequest("GET", protocol+"://"+host+"/tasks?task_id="+taskId, nil)
	if err != nil {
		return nil, err
	}
	taskReq.Header.Add("content-type", "application/json")
	taskReq.Header.Add("authorization", "token="+m.authorizationToken)

	//Execute the request
	tresp, err := m.client.Do(taskReq)
	if err == nil && tresp != nil && tresp.StatusCode == 200 {
		defer tresp.Body.Close()
		derr := json.NewDecoder(tresp.Body).Decode(&tasks)
		if derr != nil {
			return nil, derr
		}
		log.Debugf("Task Info: %+v\n", tasks)
	} else {
		sc := -1
		if tresp != nil {
			sc = tresp.StatusCode
		}

		log.Errorf("Error Task Req.  Error Code: %d  Error: %v\n", sc, err)
		return nil, err
	}

	for _, task := range tasks.Tasks {
		if task.ID == taskId {
			return task, nil
		}
	}

	return nil, fmt.Errorf("Could not find taskId %s in mesos.", taskId)
}

func (m *mesosScheduler) getMesosTask(taskId string) (*mesosTask, string, string, error) {

	var slaveHost string

	//Get the master hosts to try
	if masterHosts, protocol, err := m.getMesosMaster(); err == nil {
		//Check the Authorization Token and create if needed
		m.createAuthorizationToken()

		var masterErr error

		//Loop over the master hosts trying to get a response
		var task *mesosTask
		for _, host := range masterHosts {
			var err error
			task, err = m.getTaskInfo(taskId, protocol, host)
			if err != nil {
				masterErr = err
				continue
			} else if task == nil {
				masterErr = fmt.Errorf("Could not find taskId %s in mesos.", taskId)
				continue
			} else {
				masterErr = nil
			}
		}

		if masterErr != nil {
			return &mesosTask{}, "", "", masterErr
		}

		var slave *mesosSlave
		for _, host := range masterHosts {
			var err error
			slave, err = m.getSlaveInfo(task.SlaveID, protocol, host)
			if err != nil {
				masterErr = err
				continue
			} else if slave == nil {
				masterErr = fmt.Errorf("Could not find slaveId %s in mesos.", task.SlaveID)
				continue
			} else {
				masterErr = nil
			}
		}

		if masterErr != nil {
			log.Warnf("Mesos: Task ID %v was running on Slave %v, but no information about that slave was found.", task.ID, task.SlaveID)
		} else {
			if pid, err := upid.Parse(slave.PID); err == nil {
				slaveHost = pid.Host
			} else {
				log.Warnf("Mesos: Failed to parse PID %v.", slave.PID)
			}
		}

		var framework *mesosFramework
		for _, host := range masterHosts {
			var err error
			framework, err = m.getFrameworkInfo(task.FrameworkID, protocol, host)
			if err != nil {
				masterErr = err
				continue
			} else if framework == nil {
				masterErr = fmt.Errorf("Could not find frameworkId %s in mesos.", task.FrameworkID)
				continue
			} else {
				masterErr = nil
			}
		}

		return task, slaveHost, framework.Name, nil
	} else {
		return &mesosTask{}, "", "", err
	}
}
