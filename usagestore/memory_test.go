package usagestore

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStoreStore(t *testing.T) {
	vs, _ := NewInMemoryUsageStore()

	if err := vs.Acquire(vaultToken, "k", 1, 10*time.Minute); err == nil {
		if n, err := vs.UsageCount(vaultToken, "k"); err == nil {
			if n != 1 {
				t.Fatalf("expected usage to be 1, got %d", n)
			}
		} else {
			t.Fatalf("failed to acquire usage count for sample key k: %v", err)
		}
		if err := vs.Acquire(vaultToken, "k", 1, 10*time.Minute); err != ErrPutLimitExceeded {
			t.Fatalf("Expected ErrPutLimitExceeded but got: %v", err)
		}
		c := make(chan struct{})
		expectedSuccess := int32(10)
		success := int32(0)
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				<-c
				if err := vs.Acquire(vaultToken, "g", int(expectedSuccess), 10*time.Minute); err == nil {
					atomic.AddInt32(&success, 1)
				} else if err == ErrPutLimitExceeded {

				} else {
					t.Fatalf("Error when trying to acquire in stampede: %v", err)
				}
				wg.Done()
			}()
		}
		close(c)
		wg.Wait()
		if expectedSuccess != success {
			t.Fatalf("Expected %d acquires to succeed but got: %d", expectedSuccess, success)
		}
	} else {
		t.Fatalf("failed to acquire sample key k: %v", err)
	}

}
