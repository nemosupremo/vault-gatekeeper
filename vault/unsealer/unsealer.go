package unsealer

import (
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/franela/goreq"

	"github.com/nemosupremo/vault-gatekeeper/vault"
)

// The Unsealer interface represets a type that can retrieve a valid token
// for usage with Vault.
type Unsealer interface {
	Token() (string, error)
	Name() string
}

// The TokenUnsealer simply returns the token it was instatiated with as
// the token for Vault.
type TokenUnsealer struct {
	AuthToken string
}

// Retrieving a token with the TokenUnsealer checks that the token is still
// valid first.
func (t TokenUnsealer) Token() (string, error) {
	r, err := vault.Request{goreq.Request{
		Uri:             vault.Path("/v1/auth/token/lookup-self", ""),
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", t.AuthToken)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			return t.AuthToken, nil
		default:
			var e vault.Error
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
	r, err := vault.Request{req}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			var t struct {
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
			if err := r.Body.FromJsonTo(&t); err == nil {
				if t.Auth.ClientToken == "" && t.WrapInfo.Token != "" {
					return t.WrapInfo.Token, nil
				}
				return t.Auth.ClientToken, nil
			} else {
				return "", err
			}
		default:
			var e vault.Error
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

// The GitHubUnsealer retrieves a token from Vault using a user's Github
// personal token
type GitHubUnsealer struct {
	PersonalToken string
	genericUnsealer
}

func (gh GitHubUnsealer) Token() (string, error) {
	return gh.genericUnsealer.Token(goreq.Request{
		Uri:    vault.Path("/v1/auth/github/login", ""),
		Method: "POST",
		Body: struct {
			Token string `json:"token"`
		}{gh.PersonalToken},
		MaxRedirects:    10,
		RedirectHeaders: true,
	})
}

func (gh GitHubUnsealer) Name() string {
	return "github"
}

// The UserPassUnsealer retrieves a token from Vault using a username &
// password combiniation that is authorized with Vault already.
type UserPassUnsealer struct {
	Username string
	Password string
	Endpoint string
	genericUnsealer
}

func (u UserPassUnsealer) Token() (string, error) {
	endpoint := u.Endpoint
	if endpoint == "" {
		endpoint = "userpass"
	}
	return u.genericUnsealer.Token(goreq.Request{
		Uri:    vault.Path("/v1/auth/" + endpoint + "/login/" + u.Username),
		Method: "POST",
		Body: struct {
			Password string `json:"password"`
		}{u.Password},
		MaxRedirects:    10,
		RedirectHeaders: true,
	})
}

func (u UserPassUnsealer) Name() string {
	return "userpass"
}

// The AppRole unsealer retrives a token using RoleId and SecretId.
type AppRoleUnsealer struct {
	RoleId   string
	SecretId string
	Endpoint string
	Wrap     time.Duration
	genericUnsealer
}

func (u AppRoleUnsealer) Token() (string, error) {
	endpoint := u.Endpoint
	if endpoint == "" {
		endpoint = "approle"
	}
	req := goreq.Request{
		Uri:    vault.Path("/v1/auth/" + endpoint + "/login"),
		Method: "POST",
		Body: struct {
			RoleId   string `json:"role_id"`
			SecretId string `json:"secret_id,omitempty"`
		}{u.RoleId, u.SecretId},
		MaxRedirects:    10,
		RedirectHeaders: true,
	}
	if u.Wrap > 0 {
		req.AddHeader("X-Vault-Wrap-TTL", u.Wrap.String())
	}
	return u.genericUnsealer.Token(req)
}

func (u AppRoleUnsealer) Name() string {
	return "approle"
}

// The WrappedToken unsealer retrieves a token created by vault that was
// responsewrapped into another token.
type WrappedTokenUnsealer struct {
	TempToken string
}

var errInvalidWrappedToken = errors.New("Invalid wrapped token.")

func (t WrappedTokenUnsealer) Token() (string, error) {
	resp, err := vault.Request{
		goreq.Request{
			Uri:             vault.Path("/v1/sys/wrapping/unwrap", ""),
			MaxRedirects:    10,
			RedirectHeaders: true,
			Method:          "POST",
		}.WithHeader("X-Vault-Token", t.TempToken),
	}.Do()
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var e vault.Error
		e.Code = resp.StatusCode

		if err := resp.Body.FromJsonTo(&e); err != nil {
			e.Errors = []string{"communication error."}
			return "", e

		}

		return "", e
	}

	secretResp := struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}{}

	if err := resp.Body.FromJsonTo(&secretResp); err != nil {
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

// The AwsUnsealer uses the aws-ec2 method to authorized with Vault.
type AwsUnsealer struct {
	Role  string
	Nonce string
	genericUnsealer
}

func (aws AwsUnsealer) Token() (string, error) {
	svc := ec2metadata.New(session.New())
	pkcs7, err := svc.GetDynamicData("instance-identity/pkcs7")

	if err != nil {
		return "", err
	}

	return aws.genericUnsealer.Token(goreq.Request{
		Uri:    vault.Path("/v1/auth/aws-ec2/login", ""),
		Method: "POST",
		Body: struct {
			Role  string `json:"role,omitempty"`
			Nonce string `json:"nonce,omitempty"`
			Pkcs7 string `json:"pkcs7"`
		}{aws.Role, aws.Nonce, pkcs7},
		MaxRedirects:    10,
		RedirectHeaders: true,
	})
}

func (aws AwsUnsealer) Name() string {
	return "aws"
}
