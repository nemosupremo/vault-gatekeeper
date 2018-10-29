package main

import (
	"runtime"

	// import schedulers before cmd
	_ "vault-gatekeeper/scheduler/dcosee_mesos"
	_ "vault-gatekeeper/scheduler/ecs"
	_ "vault-gatekeeper/scheduler/mesos"

	"vault-gatekeeper/cmd"
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
