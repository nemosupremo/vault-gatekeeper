package main

import (
	//"fmt"
	//"log"
	"net/http"
	//"net/url"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"errors"
)

type ecsMetaData struct {
	ClusterName             string `json:"Cluster"`
	ContainerInstanceArn    string `json:"ContainerInstanceArn"`
	Version                 string `json:"Version"`
}

var awsSession = session.New()

func getEcsTask(taskId string) (ecs.Task, error) {
	region, err := getEcsRegion()
	if err != nil {
		return ecs.Task{}, err
	}

	ecsSrv := ecs.New(awsSession, aws.NewConfig().WithRegion(region))
	meta, err := getEcsClusterMetaData()

	if err != nil {
		return ecs.Task{}, err
	}

	params := &ecs.DescribeTasksInput{
		Tasks: []*string{ // Required
			aws.String(taskId), // Required
			// More values...
		},
		Cluster: aws.String(meta.ClusterName),
	}
	resp, err := ecsSrv.DescribeTasks(params)

	if err == nil && len(resp.Tasks) == 1 {
		return *resp.Tasks[0], err
	} else {
		if (err == nil) {
			err = errors.New("Unable to get ECS Task MetaData")
		}
	}

	return ecs.Task{}, err
}

func getEcsClusterMetaData() (ecsMetaData, error) {
	var meta        ecsMetaData
	var masterErr error

	localIp, masterErr := getEcsIp()
	if masterErr != nil {
		return ecsMetaData{}, masterErr
	}

	if resp, err := http.Get("http://" + localIp + ":51678/v1/metadata"); err == nil {
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&meta); err == nil {
			if len(meta.ClusterName) > 0 {
				masterErr = nil
			}
		} else {
			masterErr = err
		}
	} else {
		masterErr = err
	}

	if masterErr != nil {
		return ecsMetaData{}, masterErr
	}

	return meta, masterErr
}

func getEcsRegion() (string, error) {
	svc := ec2metadata.New(awsSession)
	return svc.Region()
}

func getEcsIp() (string, error) {
	svc := ec2metadata.New(awsSession)
	return svc.GetMetadata("local-ipv4")
}