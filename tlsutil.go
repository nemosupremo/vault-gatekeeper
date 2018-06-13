package main

// Based on https://stackoverflow.com/a/40883377 and
// https://github.com/robustirc/bridge/blob/v1.7.1/tlsutil/tlsutil.go.
// Originally licensed under the BSD 3-Clause license:

// Copyright © 2014-2015 The RobustIRC Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
//     * Neither the name of RobustIRC nor the names of contributors may be used
//       to endorse or promote products derived from this software without
//       specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type keypairReloader struct {
	certMutex sync.RWMutex
	cert      *tls.Certificate
	certFile  string
	keyFile   string
}

func NewKeypairReloader(certFile, keyFile string) (*keypairReloader, error) {
	result := &keypairReloader{
		certFile: certFile,
		keyFile:  keyFile,
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	result.cert = &cert
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		for range c {
			log.Printf("Received SIGHUP, reloading TLS certificate and key from %q and %q", certFile, keyFile)
			if err := result.maybeReload(); err != nil {
				log.Printf("Keeping old TLS certificate because the new one could not be loaded: %v", err)
			}
		}
	}()
	return result, nil
}

// This works just like http.ListenAndServeTLS but certificates are loaded into
// a wrapper struct that reloads certificates from disk when a SIGHUP is
// received.
func ListenAndServeTLS(addr, certFile, keyFile string, handler http.Handler) error {
	// From http.ListenAndServeTLS:
	// https://github.com/golang/go/blob/release-branch.go1.10/src/net/http/server.go#L3000-L3003
	server := &http.Server{Addr: addr, Handler: handler}

	keypair, err := NewKeypairReloader(certFile, keyFile)
	if err != nil {
		return err
	}
	server.TLSConfig = &tls.Config{GetCertificate: keypair.GetCertificateFunc()}

	// The certFile and keyFile arguments below are ignored if the GetCertificate field is not nil.
	return server.ListenAndServeTLS("", "")
}

func (kpr *keypairReloader) maybeReload() error {
	newCert, err := tls.LoadX509KeyPair(kpr.certFile, kpr.keyFile)
	if err != nil {
		return err
	}
	kpr.certMutex.Lock()
	defer kpr.certMutex.Unlock()
	kpr.cert = &newCert
	return nil
}

func (kpr *keypairReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		kpr.certMutex.RLock()
		defer kpr.certMutex.RUnlock()
		return kpr.cert, nil
	}
}
