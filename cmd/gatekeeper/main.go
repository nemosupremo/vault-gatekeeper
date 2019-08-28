package main

import (
	"runtime"

	// import schedulers before cmd
	_ "github.com/nemosupremo/vault-gatekeeper/scheduler/dcosee_mesos"
	_ "github.com/nemosupremo/vault-gatekeeper/scheduler/ecs"
	_ "github.com/nemosupremo/vault-gatekeeper/scheduler/mesos"

	"github.com/packetloop/vault-gatekeeper/cmd"
)

var (
	Version   = "--dev--"
	BuildTime = "--dev--"
)

func main() {
	cmd.Version = Version
	cmd.RootCmd.Version = Version
	runtime.GOMAXPROCS(runtime.NumCPU())
	cmd.Execute()
}
