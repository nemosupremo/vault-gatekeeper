package usagestore

import (
	"sync"
	"time"
)

type memEntry struct {
	usage   int
	created time.Time
	expire  time.Time
	max     int
}

type memoryStore struct {
	set  map[string]memEntry
	quit chan struct{}
	sync.RWMutex
}

// NewInMemoryUsageStore creates a usage store backed by memory. This usage
// store is only appropriate for single instance gatekeeper deployments
// and should not be used for high availablility deployments.
func NewInMemoryUsageStore() (UsageStore, error) {
	m := &memoryStore{}
	m.set = make(map[string]memEntry)
	m.quit = make(chan struct{})
	go m.garbageCollector()
	return m, nil
}

func (m *memoryStore) Has(_ string, key string) (bool, error) {
	m.RLock()
	_, ok := m.set[key]
	m.RUnlock()
	return ok, nil
}

func (m *memoryStore) Acquire(_ string, key string, max int, ttl time.Duration) error {
	if max < 1 {
		panic("Max must be greater than 0.")
	}
	m.Lock()
	if entry, ok := m.set[key]; ok {
		if entry.usage >= entry.max {
			m.Unlock()
			return ErrPutLimitExceeded
		}
		entry.usage += 1
		m.set[key] = entry
	} else {
		entry.usage = 1
		entry.created = time.Now()
		entry.expire = entry.created.Add(ttl)
		entry.max = max
		m.set[key] = entry
	}
	m.Unlock()
	return nil
} 

// AcquireBypassScheduler method is being used when --local-dev-mode flag is enabled. Its purpose
// is to allow faster local development where a user does not need to have a running Mesos/other
// scheduler and does not check for token num_uses. This is not meant to use in production.
func (m *memoryStore) AcquireBypassScheduler(_ string, key string,  ttl time.Duration) error {
	m.Lock()
	if entry, ok := m.set[key]; ok {
		m.set[key] = entry
	} else {
		entry.created = time.Now()
		entry.expire = entry.created.Add(ttl)
		m.set[key] = entry
	}
	m.Unlock()
	return nil
} 

func (m *memoryStore) UsageCount(_ string, key string) (int, error) {
	m.RLock()
	if e, ok := m.set[key]; ok {
		m.RUnlock()
		return e.usage, nil
	} else {
		m.RUnlock()
		return 0, nil
	}
}

func (m *memoryStore) Destroy() error {
	m.Lock()
	close(m.quit)
	m.set = nil
	m.Unlock()
	return nil
}

func (m *memoryStore) cleanup() {
	m.Lock()
	for k, v := range m.set {
		if time.Now().After(v.expire) {
			delete(m.set, k)
		}
	}
	m.Unlock()
}

func (m *memoryStore) garbageCollector() {
	ticker := time.Tick(5 * time.Second)
	for {
		select {
		case <-ticker:
			m.cleanup()
		case <-m.quit:
			return
		}
	}
}
