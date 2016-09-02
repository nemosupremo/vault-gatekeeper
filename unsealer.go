package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/franela/goreq"
	"hash"
	"io/ioutil"
	"net"
	"path"
	"strings"
)

type vaultError struct {
	Code   int      `json:"-"`
	Errors []string `json:"errors"`
}

func (e vaultError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, strings.Join(e.Errors, ", "))
}

type vaultTokenResp struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		TTL           int    `json:"ttl"`
	} `json:"auth"`
	WrapInfo struct {
		Token           string `json:"token"`
		TTL             int    `json:"ttl"`
		WrappedAccessor string `json:"wrapped_accessor"`
	} `json:"wrap_info"`
}

type Unsealer interface {
	Token() (string, error)
	Name() string
}

type TokenUnsealer struct {
	AuthToken string
}

func (t TokenUnsealer) Token() (string, error) {
	r, err := VaultRequest{goreq.Request{
		Uri:             vaultPath("/v1/auth/token/lookup-self", ""),
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", t.AuthToken)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			return t.AuthToken, nil
		default:
			var e vaultError
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return "", e
			} else {
				e.Errors = []string{"communication error."}
				return "", e
			}
		}
	} else {
		return "", err
	}
}

func (t TokenUnsealer) Name() string {
	return "token"
}

type genericUnsealer struct{}

func (g genericUnsealer) Token(req goreq.Request) (string, error) {
	r, err := VaultRequest{req}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			var t vaultTokenResp
			if err := r.Body.FromJsonTo(&t); err == nil {
				return t.Auth.ClientToken, nil
			} else {
				return "", err
			}
		default:
			var e vaultError
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return "", e
			} else {
				e.Errors = []string{"communication error."}
				return "", e
			}
		}
	} else {
		return "", err
	}
}

type AppIdUnsealer struct {
	AppId           string
	UserIdMethod    string
	UserIdInterface string
	UserIdPath      string
	UserIdHash      string
	UserIdSalt      string
	genericUnsealer
}

var errUnknownUserIdMethod = errors.New("Unknown method specified for user id.")
var errUnknownHashMethod = errors.New("Unknown hash method specified for user id.")

func (a AppIdUnsealer) Token() (string, error) {
	body := struct {
		UserId string `json:"user_id"`
	}{}
	switch a.UserIdMethod {
	case "mac":
		if iface, err := net.InterfaceByName(a.UserIdInterface); err == nil {
			body.UserId = iface.HardwareAddr.String()
		} else {
			return "", err
		}
	case "file":
		if b, err := ioutil.ReadFile(a.UserIdPath); err == nil {
			body.UserId = string(b)
		} else {
			return "", err
		}
	default:
		return "", errUnknownUserIdMethod
	}
	var hasher hash.Hash
	switch a.UserIdHash {
	case "md5":
		hasher = md5.New()
	case "sha1":
		hasher = sha1.New()
	case "sha256":
		hasher = sha256.New()
	case "":

	default:
		return "", errUnknownHashMethod
	}
	if hasher != nil {
		h := body.UserId
		if a.UserIdSalt != "" {
			h = a.UserIdSalt + "$" + h
		}
		if _, err := hasher.Write([]byte(h)); err == nil {
			body.UserId = hex.EncodeToString(hasher.Sum(nil))
		} else {
			return "", err
		}
	}
	return a.genericUnsealer.Token(goreq.Request{
		Uri:             vaultPath("/v1/auth/app-id/login/"+a.AppId, ""),
		Method:          "POST",
		Body:            body,
		MaxRedirects:    10,
		RedirectHeaders: true,
	})
}

func (a AppIdUnsealer) Name() string {
	return "app-id"
}

type GithubUnsealer struct {
	PersonalToken string
	genericUnsealer
}

func (gh GithubUnsealer) Token() (string, error) {
	return gh.genericUnsealer.Token(goreq.Request{
		Uri:    vaultPath("/v1/auth/github/login", ""),
		Method: "POST",
		Body: struct {
			Token string `json:"token"`
		}{gh.PersonalToken},
		MaxRedirects:    10,
		RedirectHeaders: true,
	})
}

func (gh GithubUnsealer) Name() string {
	return "github"
}

type UserpassUnsealer struct {
	Username string
	Password string
	genericUnsealer
}

func (u UserpassUnsealer) Token() (string, error) {
	return u.genericUnsealer.Token(goreq.Request{
		Uri:    vaultPath("/v1/auth/userpass/login/"+u.Username, ""),
		Method: "POST",
		Body: struct {
			Password string `json:"password"`
		}{u.Password},
		MaxRedirects:    10,
		RedirectHeaders: true,
	})
}

func (u UserpassUnsealer) Name() string {
	return "userpass"
}

type CubbyUnsealer struct {
	TempToken string
	Path      string
}

var errInvalidTokenCubby = errors.New("Invalid token in cubby.")

func (t CubbyUnsealer) Token() (string, error) {
	if t.Path == "" {
		t.Path = "/vault-token"
	}
	r, err := VaultRequest{goreq.Request{
		Uri:             vaultPath(path.Join("/v1/cubbyhole", t.Path), ""),
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", t.TempToken)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			vaultResp := struct {
				Data struct {
					Token string `json:"token"`
				} `json:"data"`
			}{}
			if err := r.Body.FromJsonTo(&vaultResp); err == nil {
				if vaultResp.Data.Token == "" {
					return "", errInvalidTokenCubby
				} else {
					return TokenUnsealer{vaultResp.Data.Token}.Token()
				}
			} else {
				return "", err
			}
		default:
			var e vaultError
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return "", e
			} else {
				e.Errors = []string{"communication error."}
				return "", e
			}
		}
	} else {
		return "", err
	}
}

func (t CubbyUnsealer) Name() string {
	return "cubby"
}

type WrappedTokenUnsealer struct {
	TempToken string
}

var errInvalidWrappedToken = errors.New("Invalid wrapped token.")

func (t WrappedTokenUnsealer) Token() (string, error) {
	resp, err := VaultRequest{
		goreq.Request{
			Uri:             vaultPath("/v1/cubbyhole/response", ""),
			MaxRedirects:    10,
			RedirectHeaders: true,
		}.WithHeader("X-Vault-Token", t.TempToken),
	}.Do()
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var e vaultError
		e.Code = resp.StatusCode

		if err := resp.Body.FromJsonTo(&e); err != nil {
			e.Errors = []string{"communication error."}
			return "", e

		}

		return "", e
	}

	var vaultWrappedResp VaultWrappedResponse

	if err := resp.Body.FromJsonTo(&vaultWrappedResp); err != nil {
		return "", err
	}

	secretResp := struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}{}

	if err := vaultWrappedResp.Unwrap(&secretResp); err != nil {
		return "", err
	}

	if secretResp.Auth.ClientToken == "" {
		return "", errInvalidWrappedToken
	}

	return TokenUnsealer{secretResp.Auth.ClientToken}.Token()
}

func (t WrappedTokenUnsealer) Name() string {
	return "wrapped-token"
}
