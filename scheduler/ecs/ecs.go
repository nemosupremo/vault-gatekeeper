package ecs

import (
	"net"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/franela/goreq"
	"github.com/nemosupremo/vault-gatekeeper/scheduler"
)

type ecsScheduler struct {
	Session *session.Session
	Ecs     *ecs.ECS
	Region  string
	LocalIp string
	Cluster struct {
		ClusterName          string `json:"Cluster"`
		ContainerInstanceArn string `json:"ContainerInstanceArn"`
		Version              string `json:"Version"`
	}
}

type task struct {
	id        string
	name      string
	ip        net.IP
	startTime time.Time
}

func (t task) Id() string {
	return t.id
}

func (t task) Group() string {
	return ""
}

func (t task) Image() string {
	return ""
}

func (t task) IP() net.IP {
	return t.ip
}

func (t task) Name() string {
	return t.name
}

func (t task) StartTime() time.Time {
	return t.startTime
}

func NewECSScheduler() (scheduler.Scheduler, error) {
	e := &ecsScheduler{
		Session: session.New(),
	}
	metadataSvc := ec2metadata.New(e.Session)
	var err error
	if e.Region, err = metadataSvc.Region(); err != nil {
		return nil, err
	}
	e.Ecs = ecs.New(e.Session, aws.NewConfig().WithRegion(e.Region))
	if e.LocalIp, err = metadataSvc.GetMetadata("local-ipv4"); err != nil {
		return nil, err
	}

	req := goreq.Request{
		Uri: "http://" + e.LocalIp + ":51678/v1/metadata",
	}
	if resp, err := req.Do(); err == nil {
		defer resp.Body.Close()
		if err := resp.Body.FromJsonTo(&e.Cluster); err == nil {
			return e, nil
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
}

func (e *ecsScheduler) LookupTask(taskId string) (scheduler.Task, error) {
	var t *ecs.Task
	describeTaskCmd := &ecs.DescribeTasksInput{
		Tasks: []*string{ // Required
			aws.String(taskId), // Required
		},
		Cluster: aws.String(e.Cluster.ClusterName),
	}
	resp, err := e.Ecs.DescribeTasks(describeTaskCmd)
	if err == nil && len(resp.Tasks) > 0 {
		t = resp.Tasks[0]
	}
	for i := time.Duration(0); i < 3 && err == nil && t != nil && t.StartedAt.IsZero(); i++ {
		time.Sleep((500 + 250*i) * time.Millisecond)
		resp, err = e.Ecs.DescribeTasks(describeTaskCmd)
		if err == nil && len(resp.Tasks) > 0 {
			t = resp.Tasks[0]
		}
	}

	if err == nil && len(resp.Tasks) == 1 {
		t := resp.Tasks[0]
		taskArn := *t.TaskArn
		taskDefArn := *t.TaskDefinitionArn

		ecsTaskId := taskArn[strings.Index(taskArn, "/")+1:]
		ecsTaskNameWithVersion := taskDefArn[strings.Index(taskDefArn, "/")+1:]
		ecsTaskName := ecsTaskNameWithVersion[0:strings.Index(ecsTaskNameWithVersion, ":")]

		var ip net.IP
		if len(t.Containers) > 0 && len(t.Containers[0].NetworkInterfaces) > 0 {
			ip = net.ParseIP(*(t.Containers[0].NetworkInterfaces[0].PrivateIpv4Address))
		}

		return &task{
			id:        ecsTaskId,
			name:      ecsTaskName,
			startTime: *t.StartedAt,
			ip:        ip,
		}, nil
	} else {
		if err == nil {
			err = scheduler.ErrTaskNotFound
		}
		return nil, err
	}
}
