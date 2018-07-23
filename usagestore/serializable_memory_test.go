package usagestore

import (
	"testing"
	"time"
)

func TestSerializableRoundTrip(t *testing.T) {
	m, _ := UsageSet(nil)
	m.Set("foo", memEntry{5, time.Now(), time.Now(), 1})
	m.Set("bar", memEntry{6, time.Now(), time.Now(), 1})
	m.Set("baz", memEntry{7, time.Now(), time.Now(), 1})
	b := m.Serialize()
	if m, err := UsageSet(b); err == nil {
		if len(m) != 3 {
			t.Fatalf("Expected set to be of size '3', it was %d", len(m))
		}
		if v, ok := m.Get("foo"); ok {
			if v.usage != 5 {
				t.Fatalf("Expected key 'foo' to have a usage of 5, had %d", v.usage)
			}
		} else {
			t.Fatalf("Expected key 'foo', but it wasn't found")
		}
		if v, ok := m.Get("baz"); ok {
			if v.usage != 7 {
				t.Fatalf("Expected key 'baz' to have a usage of 7, had %d", v.usage)
			}
		} else {
			t.Fatalf("Expected key 'baz', but it wasn't found")
		}
	} else {
		t.Fatalf("Failed to round trip serialize: %v", err)
	}
}
