package scheduler

import (
	"errors"
	"net"
	"time"
)

var ErrTaskNotFound = errors.New("Task not found.")

type Task interface {
	Id() string
	Group() string
	Name() string
	Image() string
	IP() net.IP
	StartTime() time.Time
}

type Scheduler interface {
	LookupTask(string) (Task, error)
}

type Args struct {
	Name        string
	Default     interface{}
	Description string
}

type NewScheduler func() (Scheduler, error)

var schedulers = make(map[string]NewScheduler)
var schedulerArgs = []Args{}

func RegisterScheduler(name string, new_ NewScheduler, args []Args) {
	schedulers[name] = new_
	schedulerArgs = append(schedulerArgs, args...)
}

func AllArgs() []Args {
	return schedulerArgs
}

func Get(name string) (NewScheduler, bool) {
	s, ok := schedulers[name]
	return s, ok
}
