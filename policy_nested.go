package main

import (
	"fmt"
	"log"
	"github.com/franela/goreq"
	"path"
	"strings"
)

type secretsList struct {
	Auth interface{} `json:"auth"`
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
	LeaseDuration int    `json:"lease_duration"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
}

func (p policies) loadNestedPolicies(authToken string) error {

	initialPolicyDir := path.Join("v1/secret", config.Vault.GkPolicies)

	/* build a list of policy directories from Vault */
	policyDirectories, err := getNestedPolicyDirs(initialPolicyDir, authToken)
	if err != nil { //if no policies at the initial Dir then return with p unchanged.
		return err
	}

	//fmt.Println("policy-nested: loadNestedPolicies: Num Dirs =", len(policyDirectories))

	/* create an empty tempPolicies. Don't overwrite original until new is successful. */
	var tempPolicies = make(policies)

	/* get policies from each policy directory and append them to the temp list. */
	for _, dir := range policyDirectories {
		/* get the policy file for the Dir */
		if err := (&tempPolicies).getPolicyFile(dir, authToken); err != nil {
				return err
		}
	}

	/* if no policy files were found then add the default. */
	if len(tempPolicies) == 0 {
		log.Printf("There was no policy in the secret backend at %v. Tokens created will have the default vault policy.", config.Vault.GkPolicies)
		for k, v := range defaultPolicies {
			tempPolicies[k] = v
		}
	}

	/* delete all from policies */
	for k := range p {
		delete(p, k)
	}

	/* Copy tempPolicies to policies */
	for k,v := range tempPolicies{
		p[k] = v
	}

	return nil
}

func getNestedPolicyDirs(initialPolicyDir string, authToken string) ([]string, error) {

	/* Start with empty lists */
	var nestedPolicyDirs []string
	var subDirs []string
	/* always add the initial dir because it won't have a "/" suffix. */
	nestedPolicyDirs = append(nestedPolicyDirs, initialPolicyDir)

	err := getDirList(initialPolicyDir, authToken, &nestedPolicyDirs, &subDirs)
	if err != nil {
		return nestedPolicyDirs, err
	}

	/* loop through subDirs until no more entries have a suffix of "/" */
	moreSubDirectories := true
	for moreSubDirectories  {
		moreSubDirectories = false
		for i, subDir := range subDirs {
			if strings.HasSuffix(subDir, "/") { //subDir should always end with "/"
				moreSubDirectories = true
				//remove the "/" suffix to indicate that it has been processed. (abc/ becomes abc)
				subDirs[i] = strings.TrimSuffix(subDir, "/")
				err = getDirList(subDirs[i], authToken, &nestedPolicyDirs, &subDirs)
				if err != nil {
					return nestedPolicyDirs, err
				}
				break //restart range at the beginning instead of continuing. Will keep hierarchical dir order.
			}
		}
	}

//	fmt.Println("policy-nested: getNestedPolicyDirs: final list: nestedPolicyDirs =", nestedPolicyDirs)
//	fmt.Println("policy-nested: getNestedPolicyDirs: final list: subDirs =", subDirs)

	return nestedPolicyDirs, err
}

func getDirList (path string, authToken string, nestedPolicies *[]string, subDirs *[]string) (error) {

	r, err := VaultRequest{goreq.Request{
		Uri:             vaultPath(path, "list=true"),
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", authToken)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			scrts := new(secretsList)

			if err := r.Body.FromJsonTo(&scrts); err == nil {
				for i := range scrts.Data.Keys {
//					fmt.Println("policy-nested: getDirList: keys: #", i, " value =", scrts.Data.Keys[i])

					if strings.HasSuffix(scrts.Data.Keys[i], "/") { //add to sub dir list when "/" suffix
						*subDirs = append(*subDirs, path + "/" + scrts.Data.Keys[i])
					} else {
						*nestedPolicies = append(*nestedPolicies, path + "/" + scrts.Data.Keys[i])
					}
				}
			} else {
				log.Printf("There was an error decoding the secrets list from vault where path = %v. Err = %v", path, err)
			}
		case 404:
			/* A 404 is returned when no sub directories exist below the current directory which is ok. */
			log.Printf("Vault returned a 404. There are no sub directories below this path. %v", path)
		default:
			var e vaultError
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				log.Printf(e.Error())
			} else {
				e.Errors = []string{"communication error.", " getDirList: path = " + path}
				log.Printf(e.Error())
			}
			if e.Code < 201 || e.Code > 299 {
				err = e
			}
		}
	} else {
		var e vaultError
		e.Code = 503
		e.Errors = []string{fmt.Sprint("Error doing a 'List' from vault at ", path, ". Error = ", err.Error())}
		err = e
		fmt.Printf(err.Error())
	}

	return err
}

func (tempPolicies policies) getPolicyFile (path string, authToken string) (error) {

	r, err := VaultRequest{goreq.Request{
		Uri:             vaultPath(path, ""),
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", authToken)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:

			resp := struct {
				Data policies `json:"data"`
			}{}

			if err := r.Body.FromJsonTo(&resp); err == nil {
				for k, v := range resp.Data {
					//fmt.Println("policy-nested: getPolicyFile: Key =", k, " Value =", v)
					if _, ok := tempPolicies[k]; ok == true { //k already in map
						/* report the fact that the Key is already in the map. Then continue. */
						log.Printf("policy-nested: getPolicyFile: Policy Key = '%v' already exists and " +
							"was not loaded. Dup found in Path = %v.", k, path)
					} else {
						tempPolicies[k] = v
					}
				}
			} else {
				err = policyLoadError{fmt.Errorf("There was an error decoding policy from vault. This can occur " +
					"when using vault-cli to save the policy json, as vault-cli saves it as a string rather than a json object.")}
				fmt.Printf(err.Error())
			}
		case 404:
			log.Printf("There was no policy in the secret backend at %v", path)
		default:
			var e vaultError
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				log.Printf(e.Error())
			} else {
				e.Errors = []string{"communication error.", " getPolicyFile: path = " + path}
				log.Printf(e.Error())
			}
			if e.Code < 201 || e.Code > 299 {
				err = e
			}
		}
	} else {
		var e vaultError
		e.Code = 503
		e.Errors = []string{fmt.Sprint("There was an error getting the policy file from vault at ", path, ". Error = ", err.Error())}
		err = e
		fmt.Printf(err.Error())
	}

	return err
}
