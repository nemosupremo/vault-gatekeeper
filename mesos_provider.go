package main

import "time"

func mesosProvider(taskId string) (RunningTask, error) {
	task, err := getMesosTask(taskId)
	for i := time.Duration(0); i < 3 && err == nil && len(task.Statuses) == 0; i++ {
		time.Sleep((500 + 250*i) * time.Millisecond)
		task, err = getMesosTask(taskId)
	}
	runningTime := time.Unix(0, 0)
	if len(task.Statuses) > 0 {
		// https://github.com/apache/mesos/blob/a61074586d778d432ba991701c9c4de9459db897/src/webui/master/static/js/controllers.js#L148
		runningTime = time.Unix(0, int64(task.Statuses[0].Timestamp*1000000000))
	}

	return RunningTask{
		Id:        task.Id,
		Name:      task.Name,
		StartTime: runningTime,
	}, err
}
