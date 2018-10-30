package gatekeeper

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/nemosupremo/vault-gatekeeper/policy"
	"github.com/nemosupremo/vault-gatekeeper/vault"

	"github.com/franela/goreq"
)

var policyNotFound = errors.New("No policy saved at configured location.")

type policyLoadError struct {
	Err error `json:"error"`
}

func (ple policyLoadError) Error() string {
	return fmt.Sprintf("Error loading policy from vault: %v", ple.Err)
}

func (g *Gatekeeper) loadPolicies() (*policy.Policies, error) {
	if conf, err := g.GetPolicyConfig(); err == nil {
		return policy.LoadPoliciesFromJson(conf)
	} else {
		return nil, err
	}
}

func (g *Gatekeeper) GetPolicyConfig() ([]byte, error) {
	initialPolicyDir := g.config.PolicyPath
	policies := make(map[string]policy.Policy)
	log.Debugf("Policy Dir: %s\n", initialPolicyDir)
	if policyDirectories, err := g.getNestedPolicyDirs(initialPolicyDir, g.Token); err == nil {
		for _, dir := range policyDirectories {
			log.Debugf("Dir: %s\n", dir)
			if policy, err := getPolicy(dir, g.Token); err == nil {
				log.Debugf("Policies: %+v\n", policy)
				for k, v := range policy {
					policies[k] = v
				}
			} else if err == policyNotFound {
				log.Warnf("%v\n", policyNotFound)
				continue
			} else {
				return nil, err
			}
		}
	} else {
		log.Errorf("Failed to find direcotries in %s\n", initialPolicyDir)
		return nil, err
	}

	log.Debugf("Policies: %+v\n", policies)
	if len(policies) == 0 {
		return nil, policyNotFound
	}
	return json.MarshalIndent(policies, "", "\t")
}

func (g *Gatekeeper) getNestedPolicyDirs(initialPolicyDir string, authToken string) ([]string, error) {
	// Start with empty list
	var nestedPolicyDirs []string
	var subDirs []string

	// always add the initial dir because it won't have a "/" suffix.
	nestedPolicyDirs = append(nestedPolicyDirs, initialPolicyDir)

	err := g.getDirList(initialPolicyDir, authToken, &nestedPolicyDirs, &subDirs)
	if err != nil {
		log.Errorf("Error getting dir list: %v\n", err)
		return nestedPolicyDirs, err
	}

	/* loop through subDirs until no more entries have a suffix of "/" */
	moreSubDirectories := true
	for moreSubDirectories {
		moreSubDirectories = false
		for i, subDir := range subDirs {
			if strings.HasSuffix(subDir, "/") { //subDir should always end with "/"
				moreSubDirectories = true
				//remove the "/" suffix to indicate that it has been processed. (abc/ becomes abc)
				subDirs[i] = strings.TrimSuffix(subDir, "/")
				err = g.getDirList(subDirs[i], authToken, &nestedPolicyDirs, &subDirs)
				if err != nil {
					return nestedPolicyDirs, err
				}
				break //restart range at the beginning instead of continuing. Will keep hierarchical dir order.
			}
		}
	}

	log.Debugf("Nested Policy Dirs: %+v\n", nestedPolicyDirs)

	return nestedPolicyDirs, err
}

func (g *Gatekeeper) getDirList(path string, authToken string, nestedPolicies *[]string, subDirs *[]string) error {
	uri := path
	if g.config.Vault.KvVersion == "2" {
		uri = strings.Replace(path, "/data/", "/metadata/", 1)
	}
	r, err := vault.Request{goreq.Request{
		Uri:             vault.Path(uri+"/", "list=true"),
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", authToken)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			var scrts struct {
				Auth interface{} `json:"auth"`
				Data struct {
					Keys []string `json:"keys"`
				} `json:"data"`
				LeaseDuration int    `json:"lease_duration"`
				LeaseID       string `json:"lease_id"`
				Renewable     bool   `json:"renewable"`
			}
			if err := r.Body.FromJsonTo(&scrts); err == nil {
				log.Debugf("Secrets List Data: %+v\n", scrts)
				for i := range scrts.Data.Keys {
					//add to sub dir list when "/" suffix
					if strings.HasSuffix(scrts.Data.Keys[i], "/") {
						*subDirs = append(*subDirs, path+"/"+scrts.Data.Keys[i])
					} else {
						*nestedPolicies = append(*nestedPolicies, path+"/"+scrts.Data.Keys[i])
					}
				}
				return nil
			} else {
				log.Errorf("Get Dir List: %+v\n", err)
				return err
			}
		case 404:
			/* A 404 is returned when no sub directories exist below the current directory which is ok. */
			log.Infof("Get Dir List is empty\n")
			return nil

		case 403:
			log.Warnf("403 Permission Denied when trying to list policy %v", uri+"/")
			fallthrough
		default:
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err != nil {
				e.Errors = []string{"communication error.", " getDirList: path = " + path}

			}
			return e
		}
	} else {
		return err
	}
}

func getPolicy(path string, authToken string) (map[string]policy.Policy, error) {
	r, err := vault.Request{goreq.Request{
		Uri:             vault.Path(path),
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", authToken)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			var resp struct {
				Data struct {
					Data map[string]policy.Policy `json:"data"`
				} `json:"data"`
			}
			if err := r.Body.FromJsonTo(&resp); err == nil {
				log.Debugf("Response Body: %+v\n", resp)
				return resp.Data.Data, nil
			} else {
				return nil, policyLoadError{fmt.Errorf("There was an error decoding policy from vault. This can occur " +
					"when using vault-cli to save the policy json, as vault-cli saves it as a string rather than a json object.")}
			}
		case 404:
			return nil, policyNotFound
		case 403:
			log.Warnf("403 Permission Denied when trying to get policy %v", path)
			fallthrough
		default:
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return nil, e
			} else {
				e.Errors = []string{"communication error.", " getPolicyFile: path = " + path}
				return nil, e
			}
		}
	} else {
		var e vault.Error
		e.Code = 503
		e.Errors = []string{fmt.Sprint("There was an error getting the policy file from vault at ", path, ". Error = ", err.Error())}
		return nil, e
	}
}
