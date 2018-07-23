package mesos

import (
	"os"
	"testing"
)

var testMesosMaster = os.Getenv("MESOS_MASTER")

func TestGetMesos(t *testing.T) {
	if len(testMesosMaster) == 0 {
		t.Skip()
	} else {
		if _, err := NewMesosScheduler(testMesosMaster); err != nil {
			t.Fatalf("Failed to get mesos masters: %v", err)
		}
	}
}
