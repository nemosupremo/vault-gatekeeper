package mock

import (
	"github.com/nemosupremo/vault-gatekeeper/scheduler"
)

func init() {
	scheduler.RegisterScheduler("mock", NewMockScheduler, Args())
}

type args struct {
	Name        string
	Default     interface{}
	Description string
}

func Args() []scheduler.Args {
	return []scheduler.Args{}
}
