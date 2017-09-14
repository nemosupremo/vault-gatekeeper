package main

import (
	"sync"
	"time"
)

type entry struct {
	tstamp     time.Time
	fetchCount int
}

type TtlSet struct {
	sync.RWMutex
	s    map[string]entry
	quit chan struct{}
}

func NewTtlSet() *TtlSet {
	t := &TtlSet{}
	t.s = make(map[string]entry)
	t.quit = make(chan struct{})
	go t.garbageCollector()
	return t
}

func (t *TtlSet) Has(key string) bool {
	t.RLock()
	defer t.RUnlock()
	_, ok := t.s[key]
	return ok
}

func (t *TtlSet) Put(key string, ttl time.Duration) {
	t.Lock()
	a := t.s[key]
	if a.fetchCount == 0 {
		a.tstamp = time.Now().Add(ttl)
	}
	a.fetchCount = a.fetchCount + 1
	t.s[key] = a
	t.Unlock()
}

func (t *TtlSet) UsageCount(key string) int {
	//zz := t.s[key]
	//return zz.fetchCount
	return t.s[key].fetchCount
}

func (t *TtlSet) Destroy() {
	t.Lock()
	close(t.quit)
	t.s = nil
	t.Unlock()
}

func (t *TtlSet) cleanup() {
	t.Lock()
	for k, v := range t.s {
		if time.Now().After(v.tstamp) {
			delete(t.s, k)
		}
	}
	t.Unlock()
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
