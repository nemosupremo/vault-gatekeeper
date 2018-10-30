package dcosee_mesos

import (
	"os"

	"github.com/nemosupremo/vault-gatekeeper/scheduler"

	"github.com/spf13/viper"
)

func init() {
	scheduler.RegisterScheduler("dcosee-mesos", newMesosScheduler, Args())
}

type args struct {
	Name        string
	Default     interface{}
	Description string
}

func Args() []scheduler.Args {
	return []scheduler.Args{
		// {"mesos-master", "http://localhost:5050", "Address to mesos masters in either zookeeper (zk://zoo1:2181,zoo2:2181/path) or http format http://master:5050,master:5050/."},
		{"dcos-uid", "vgm", "DCOS Enterprise requires all calls to mesos be protected with a userid and privatekey.  The is the userid of the service account for VGM to use."},
		{"dcos-privatekey", "/certs/vgm-privatekey.pem", "DCOS Enterprise requires all calls to mesos be protected with a userid and privatekey.  The is the privatekey to sign the jwt login with for the service"},
		{"mesos-skipverify", false, "If mesos is using TLS then do we need to veify the tls cert."},
	}
}

func newMesosScheduler() (scheduler.Scheduler, error) {
	master := viper.GetString("mesos-master")
	uid := viper.GetString("dcos-uid")
	privateKeyFile := viper.GetString("dcos-privatekey")
	pkRdr, err := os.Open(privateKeyFile)
	if err != nil {
		return nil, err
	}

	return NewMesosScheduler(master, uid, pkRdr)
}
