package main

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

func mesosTestProvider(taskId string) (RunningTask, error) {
	parts := strings.Split(taskId, ".")
	if len(parts) == 2 && parts[0] != "" {
		return RunningTask{
			Id: taskId,
			Name: parts[0],
			StartTime: time.Now(),
		}, nil
	} else {
		return RunningTask{
			Id: fmt.Sprintf("%s.%d", parts[0], rand.Int()),
			Name: parts[0],
			StartTime: time.Now(),
		}, nil
	}
}
