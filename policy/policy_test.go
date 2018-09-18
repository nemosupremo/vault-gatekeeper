package policy

import (
	"testing"
)

const samplePolicy = `{
	"*":{
		"roles":["wildcard"],
		"num_uses": 1
	},
	"*:invalid":{
		"roles":["invalid"],
		"num_uses":1
	},
	"mesos":{
		"roles":["only_mesos"],
		"num_uses":2
	},
	"mesos:*":{
		"roles":["mesos_child"],
		"num_uses":1
	},
	"mesos:framework":{
		"roles":["mesos_framework"],
		"num_uses":1
	},
	"mesos:framework:*":{
		"roles":["mesos_framework_child"],
		"num_uses":1
	},
	"mesos:framework:task":{
		"roles":["mesos_framework_task"],
		"num_uses":1
	},
	"mesos:framework:task2":{
		"roles":["mesos_framework_task2"],
		"num_uses":1
	},
	"mesos:framework:service/*": {
	    "roles":["mesos_framework_service"],
	    "num_uses":1
	}
}`

func shouldContainAll(p *Policy, roles ...string) (bool, []string, []string) {
	has := make([]bool, len(roles))
	had := []string{}
	for _, appid := range p.Roles {
		for ix, shouldHave := range roles {
			if shouldHave == appid {
				has[ix] = true
				had = append(had, appid)
				break
			}
		}
	}
	if len(roles) != len(p.Roles) {
		return false, roles, p.Roles
	}
	for _, h := range has {
		if h == false {
			return false, roles, p.Roles
		}
	}
	return true, nil, nil
}

func TestSamplePolicy(t *testing.T) {
	if pols, err := LoadPoliciesFromJson([]byte(samplePolicy)); err == nil {
		mustGet := func(p *Policy, b bool) *Policy {
			return p
		}
		if pass, expected, actual := shouldContainAll(mustGet(pols.Get("foo")), "wildcard"); !pass {
			t.Fatalf("Test of '%s' failed. Expected: %v Had: %v", "foo", expected, actual)
		}

		if pass, expected, actual := shouldContainAll(mustGet(pols.Get("mesos")), "wildcard", "only_mesos"); !pass {
			t.Fatalf("Test of '%s' failed. Expected: %v Had: %v", "mesos", expected, actual)
		}

		if pass, expected, actual := shouldContainAll(mustGet(pols.Get("mesos:jamp")), "wildcard", "mesos_child"); !pass {
			t.Fatalf("Test of '%s' failed. Expected: %v Had: %v", "mesos:jamp", expected, actual)
		}

		if pass, expected, actual := shouldContainAll(mustGet(pols.Get("mesos:framework:service/instance-1")), "wildcard", "mesos_child", "mesos_framework_child", "mesos_framework_service"); !pass {
			t.Fatalf("Test of '%s' failed. Expected: %v Had: %v", "mesos:framework:service/instance-1", expected, actual)
		}

		if pass, _, actual := shouldContainAll(mustGet(pols.Get("mesos:framework:task2")), "mesos_framework_task"); pass {
			t.Fatalf("Test of '%s' failed. 'task2' should not conatain permission of 'task'. Had: %v", "mesos:framework:task", actual)
		}

		if policy, ok := pols.Get("mesos:framework:task"); ok {
			if policy.Roles[0] != "mesos_framework_task" {
				t.Fatalf("Expected most specific role of '%s'. Had: %v", "mesos:framework:task", policy.Roles[0])
			}
		} else {
			t.Fatalf("Test of '%s' failed. Expected: %v Had: %v", "foo", "mesos:framework:task", policy.Roles)
		}
	} else {
		t.Fatalf("Failed to parse policy from json: %v", err)
	}
}
