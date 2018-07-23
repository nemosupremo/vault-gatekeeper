package vault

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/franela/goreq"
	"github.com/spf13/viper"
)

type Request struct {
	goreq.Request
}

func (r Request) Do() (*goreq.Response, error) {
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

func Addr() string {
	return viper.GetString("vault-addr")
}

func Path(path string, query ...interface{}) string {
	u, _ := url.Parse(Addr())
	u.Path = path
	if len(query) > 0 {
		switch q := query[0].(type) {
		case url.Values:
			u.RawQuery = q.Encode()
		case string:
			u.RawQuery = q
		default:
			panic("Invalid value passed to vault.Path()")
		}
	}
	return u.String()
}

type Error struct {
	Code   int      `json:"-"`
	Errors []string `json:"errors"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, strings.Join(e.Errors, ", "))
}
