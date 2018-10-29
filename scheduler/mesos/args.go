package mesos

import (
	"vault-gatekeeper/scheduler"

	"github.com/spf13/viper"
)

func init() {
	scheduler.RegisterScheduler("mesos", newMesosScheduler, Args())
}

type args struct {
	Name        string
	Default     interface{}
	Description string
}

func Args() []scheduler.Args {
	return []scheduler.Args{
		{"mesos-master", "http://localhost:5050", "Address to mesos masters in either zookeeper (zk://zoo1:2181,zoo2:2181/path) or http format http://master:5050,master:5050/."},
	}
}

func newMesosScheduler() (scheduler.Scheduler, error) {
	return NewMesosScheduler(viper.GetString("mesos-master"))
}
