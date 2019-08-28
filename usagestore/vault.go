package usagestore

import (
	"errors"
	"math/rand"
	"path"
	"time"

	"github.com/nemosupremo/vault-gatekeeper/vault"

	"github.com/franela/goreq"
	log "github.com/sirupsen/logrus"
)

var errCasViolation = errors.New("cas violation")

type VaultTokenGetter interface {
	VaultToken() string
}

type vaultStore struct {
	path string
}

func NewVaultStore(path string) (UsageStore, error) {
	z := &vaultStore{
		path: path,
	}
	return z, nil
}

func (v *vaultStore) getStore(token string) (SerializableUsageSet, int, error) {
	r, err := vault.Request{goreq.Request{
		Uri:             vault.Path(path.Join("v1", v.path)),
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", token)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200:
			var resp struct {
				Data struct {
					Data struct {
						Set []byte `json:"set"`
					} `json:"data"`
					Metadata struct {
						Version int `json:"version"`
					} `json:"metadata"`
				} `json:"data"`
			}
			if err := r.Body.FromJsonTo(&resp); err == nil {
				if resp.Data.Metadata.Version == 0 {
					// if the version is 0, we are using the wrong kv backend
					return nil, 0, errors.New("The kv backend reported an invalid version. Ensure your kv backend is on version 2.")
				}
				if m, err := UsageSet(resp.Data.Data.Set); err == nil {
					return m, resp.Data.Metadata.Version, nil
				} else {
					return nil, 0, err
				}
			} else {
				return nil, 0, err
			}
		case 404:
			m, _ := UsageSet(nil)
			return m, 0, nil
		case 403:
			log.Warnf("403 Permission Denied when trying to get usage store from vault at %v", v.path)
			fallthrough
		default:
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				return nil, 0, e
			} else {
				e.Errors = []string{"communication error."}
				return nil, 0, e
			}
		}
	} else {
		return nil, 0, err
	}
}

func (v *vaultStore) putStore(token string, version int, m SerializableUsageSet) error {
	var body struct {
		Data struct {
			Set []byte `json:"set"`
		} `json:"data"`
		Options struct {
			Cas int `json:"cas"`
		} `json:"options"`
	}
	body.Data.Set = m.Serialize()
	body.Options.Cas = version
	r, err := vault.Request{goreq.Request{
		Uri:             vault.Path(path.Join("v1", v.path)),
		Method:          "POST",
		Body:            body,
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.WithHeader("X-Vault-Token", token)}.Do()
	if err == nil {
		defer r.Body.Close()
		switch r.StatusCode {
		case 200, 204:
			return nil
		case 403:
			log.Warnf("403 Permission Denied when trying to get usage store from vault at %v", v.path)
			fallthrough
		default:
			var e vault.Error
			e.Code = r.StatusCode
			if err := r.Body.FromJsonTo(&e); err == nil {
				if len(e.Errors) > 0 && e.Errors[0] == "check-and-set parameter did not match the current version" {
					return errCasViolation
				}
				return e
			} else {
				e.Errors = []string{"communication error."}
				return e
			}
		}
	} else {
		return err
	}
}

func (v *vaultStore) Has(token string, key string) (bool, error) {
	if m, _, err := v.getStore(token); err == nil {
		_, ok := m.Get(key)
		return ok, nil
	} else {
		return false, err
	}
}

func (v *vaultStore) Acquire(token string, key string, max int, ttl time.Duration) error {
	if max < 1 {
		panic("Max must be greater than 0.")
	}
	if m, version, err := v.getStore(token); err == nil {
		if entry, ok := m.Get(key); ok {
			entry.usage += 1
			m.Set(key, entry)
		} else {
			entry.usage = 1
			entry.created = time.Now()
			entry.expire = entry.created.Add(ttl)
			entry.max = max
			m.Set(key, entry)
		}
		m.Cleanup()
		if err := v.putStore(token, version, m); err == nil {
			return nil
		} else if err == errCasViolation {
			n := rand.Int63n(500)
			time.Sleep(time.Millisecond * time.Duration(n))
			return v.Acquire(token, key, max, ttl)
		} else {
			return err
		}
	} else {
		return err
	}
}

// AcquireBypassScheduler method is being used when --local-dev-mode flag is enabled. Its purpose
// is to allow faster local development where a user does not need to have a running Mesos/other
// scheduler and does not check for token num_uses. This is not meant to use in production.
func (v *vaultStore) AcquireBypassScheduler(token string, key string, ttl time.Duration) error {

	if m, version, err := v.getStore(token); err == nil {
		if entry, ok := m.Get(key); ok {
			m.Set(key, entry)
		} else {
			entry.created = time.Now()
			entry.expire = entry.created.Add(ttl)
			m.Set(key, entry)
		}
		m.Cleanup()
		if err := v.putStore(token, version, m); err == nil {
			return nil
		} else if err == errCasViolation {
			n := rand.Int63n(500)
			time.Sleep(time.Millisecond * time.Duration(n))
			return v.AcquireBypassScheduler(token, key, ttl)
		} else {
			return err
		}
	} else {
		return err
	}
}

func (v *vaultStore) UsageCount(token string, key string) (int, error) {
	if m, _, err := v.getStore(token); err == nil {
		if v, ok := m.Get(key); ok {
			return v.usage, nil
		} else {
			return 0, nil
		}
	} else {
		return 0, err
	}
}

func (v *vaultStore) Destroy() error {
	return nil
}
