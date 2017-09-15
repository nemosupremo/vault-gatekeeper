package main

import (
	"sync"
	"time"
)

type entry struct {
	tstamp     time.Time
	fetchCount int
}

type LockedEntry struct {
	e map[string]entry
	sync.RWMutex
}

type TtlSet struct {
	sync.RWMutex
	s    LockedEntry
	quit chan struct{}
}

func NewTtlSet() *TtlSet {
	t := &TtlSet{}
	t.s.e = make(map[string]entry)
	t.quit = make(chan struct{})
	go t.garbageCollector()
	return t
}

func (t *TtlSet) Has(key string) bool {
	t.s.RLock()
	defer t.s.RUnlock()
	_, ok := t.s.e[key]
	return ok
}

func (t *TtlSet) Put(key string, ttl time.Duration) {
	t.s.Lock()
	a := t.s.e[key]
	if a.fetchCount == 0 {
		a.tstamp = time.Now().Add(ttl)
	}
	a.fetchCount = a.fetchCount + 1
	t.s.e[key] = a
	t.s.Unlock()
}

func (t *TtlSet) UsageCount(key string) int {
	return t.s.e[key].fetchCount
}

func (t *TtlSet) Destroy() {
	t.s.Lock()
	close(t.quit)
	t.s.e = nil
	t.s.Unlock()
}

func (t *TtlSet) cleanup() {
	t.s.Lock()
	for k, v := range t.s.e {
		if time.Now().After(v.tstamp) {
			delete(t.s.e, k)
		}
	}
	t.s.Unlock()
}

func (t *TtlSet) garbageCollector() {
	ticker := time.Tick(5 * time.Second)
	for {
		select {
		case <-ticker:
			t.cleanup()
		case <-t.quit:
			return
		}
	}
}
