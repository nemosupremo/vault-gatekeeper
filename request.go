package main

import (
	"github.com/franela/goreq"
	"io"
	"io/ioutil"
	"net/http"
)

type VaultRequest struct {
	goreq.Request
}

func (r VaultRequest) Do() (*goreq.Response, error) {
	config := goreq.DefaultTransport.(*http.Transport).TLSClientConfig
	if config != nil {
		r.Insecure = config.InsecureSkipVerify
	}
	resp, err := r.Request.Do()
	for err == nil && resp.StatusCode == 307 {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
		r.Request.Uri = resp.Header.Get("Location")
		resp, err = r.Request.Do()
	}
	return resp, err
}