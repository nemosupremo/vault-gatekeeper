package main

import "time"

func testProvider(taskId string) (RunningTask, error) {
	return RunningTask{
		Id:        taskId,
		Name:      "Test",
		StartTime: time.Now(),
	}, nil
}
