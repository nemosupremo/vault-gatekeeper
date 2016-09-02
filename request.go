package main

import (
	"encoding/json"
	"github.com/franela/goreq"
	"io"
	"io/ioutil"
)

type VaultRequest struct {
	goreq.Request
}

func (r VaultRequest) Do() (*goreq.Response, error) {
	resp, err := r.Request.Do()
	for err == nil && resp.StatusCode == 307 {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
		r.Request.Uri = resp.Header.Get("Location")
		resp, err = r.Request.Do()
	}
	return resp, err
}

type VaultWrappedResponse struct {
	Data struct {
		WrappedSecret string `json:"response"`
	} `json:"data"`
}

func (vr *VaultWrappedResponse) Unwrap(v interface{}) error {
	return json.Unmarshal([]byte(vr.Data.WrappedSecret), v)
}
