package gatekeeper

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Loads the certificate from given path and creates a certificate pool from it.
func LoadCACert(path string) (*x509.CertPool, error) {
	result := x509.NewCertPool()
	if err := appendPEMCertsFromPath(result, path); err != nil {
		return nil, err
	}

	return result, nil
}

// Loads the certificates present in the given directory or file and creates a
// certificate pool from it. Assumes that _only_ PEM formatted cert files
// are present in the given directory. The presence of other files will
// cause this to fail.
func LoadCAPath(path string) (*x509.CertPool, error) {
	result := x509.NewCertPool()

	// filepath.WalkFunc to traverse the directory structure, starting from input path
	// attempting to load certs into result in the process
	appendCerts := func(path string, info os.FileInfo, err error) error {
		// cascade errors to the end of the traversal,
		//  we fail early if there are files other than certs under path
		if err != nil {
			return err
		}

		// ignore dirs
		if info.IsDir() {
			return nil
		}

		// try and append certs from files
		if err := appendPEMCertsFromPath(result, path); err != nil {
			// fail if we can't append PEM certs or get no PEM certs from a file
			return err
		}

		return nil
	}

	// if we error while walking with appendCerts, don't return any certs
	if err := filepath.Walk(path, appendCerts); err != nil {
		return nil, err
	}

	return result, nil
}

func appendPEMCertsFromPath(certPool *x509.CertPool, path string) error {
	pemCerts, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	if ok := certPool.AppendCertsFromPEM(pemCerts); !ok {
		return fmt.Errorf("No PEM certs could be parsed from %s", path)
	}

	return nil
}
