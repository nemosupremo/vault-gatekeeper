package usagestore

import (
	"errors"
	"time"
)

var ErrPutLimitExceeded = errors.New("Put limit exceeded.")

// UsageStore stores the state about the tokens that Gatekeeper has issued and
// how many times a certain process has requested a key. UsageStore
// implementations are expected to support access by multiple goroutines.
type UsageStore interface {
	// Should return true if the store has information about this process.
	Has(string, string) (bool, error)

	// Log information about the issue of a token and how long the store should
	// remember this information. Acquire should only succeed if the usage count
	// is less than the max provided. The duration should be longer than the
	// time window for valid token requests. Ex. if the configuration dictates
	// that Gatekeeper will only issue tokens to tasks in the first 2 minutes
	// of their lifetime, then this paramter should be 2m30s.
	// Acquire should panic if max is less than 1.
	Acquire(string, string, int, time.Duration) error

	// AcquireBypassScheduler is a hack to make local-dev-mode work. This bypass
	// any scheduler check and policy num users. Intended for local developement
	// where user do not have to have a running scheduler such as Mesos.
	AcquireBypassScheduler(string, string, time.Duration) error

	// How many times a process requested a token.
	UsageCount(string, string) (int, error)

	// Destroy this usage store, close any connectinos and release any
	// resources.
	Destroy() error
}
