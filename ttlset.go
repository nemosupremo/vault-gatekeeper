package main

import (
	"sync"
	"time"
)

type TtlSet struct {
	sync.RWMutex
	s    map[string]time.Time
	quit chan struct{}
}

func NewTtlSet() *TtlSet {
	t := &TtlSet{}
	t.s = make(map[string]time.Time)
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
	t.s[key] = time.Now().Add(ttl)
	t.Unlock()
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
		if time.Now().After(v) {
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
