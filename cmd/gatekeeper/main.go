package main

import (
	"runtime"

	// import schedulers before cmd
	_ "github.com/nemosupremo/vault-gatekeeper/scheduler/ecs"
	_ "github.com/nemosupremo/vault-gatekeeper/scheduler/mesos"

	"github.com/nemosupremo/vault-gatekeeper/cmd"
)

var (
	Version   = "--dev--"
	BuildTime = "--dev--"
)

func main() {
	cmd.Version = Version
	runtime.GOMAXPROCS(runtime.NumCPU())
	cmd.Execute()
}
