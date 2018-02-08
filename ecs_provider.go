package main

import (
	"time"
	"strings"
	"log"
)

func ecsProvider(taskId string) (RunningTask, error) {
	task, err := getEcsTask(taskId)
	for i := time.Duration(0); i < 3 && err == nil && task.StartedAt.IsZero(); i++ {
		time.Sleep((500 + 250 * i) * time.Millisecond)
		task, err = getEcsTask(taskId)
	}

	if err == nil {
		var taskArn string = *task.TaskArn
		var taskDefArn string = *task.TaskDefinitionArn

		ecsTaskId := taskArn[strings.Index(taskArn, "/") + 1:]
		ecsTaskNameWithVersion := taskDefArn[strings.Index(taskDefArn, "/") + 1:]
		ecsTaskName := ecsTaskNameWithVersion[0:strings.Index(ecsTaskNameWithVersion, ":")]

		return RunningTask{
			Id:         ecsTaskId,
			Name:       ecsTaskName,
			StartTime:  *task.StartedAt,
		}, err
	} else {
		log.Printf("Unable to retrieve ECS Task information for %s: %v", taskId, err)
	}
	return RunningTask{}, err
}