package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/hashicorp/go-immutable-radix"
)

type Policy struct {
	Roles         []string `json:"roles"`
	NumUses       int      `json:"num_uses"`
	strictestPath []byte
}

func (p *Policy) merge(path []byte, other Policy) {
	if len(p.Roles) == 0 && p.NumUses == 0 {
		*p = other
		p.strictestPath = path
	} else {
		if len(path) > len(p.strictestPath) {
			p.NumUses = other.NumUses
			p.strictestPath = path
		}
		p.Roles = append(p.Roles, other.Roles...)
	}
}

func (p *Policy) Has(role string) bool {
	for _, v := range p.Roles {
		if v == role {
			return true
		}
	}
	return false
}

type Policies struct {
	*iradix.Tree
}

func LoadPoliciesFromJson(data []byte) (*Policies, error) {
	var pol map[string]Policy
	if err := json.Unmarshal(data, &pol); err == nil {
		tree := iradix.New()
		txn := tree.Txn()
		for k, v := range pol {
			if strings.HasSuffix(k, ":") {
				return nil, errors.New("Invalid key name '" + k + "'. Keys must not end with a ':'")
			}
			if v.NumUses < 1 {
				return nil, errors.New("Invalid num_uses for key '" + k + "'.")
			}
			if k != "*" {
				k = strings.TrimSuffix(k, "*")
			}
			txn.Insert([]byte(k), v)
		}
		tree = txn.Commit()
		return &Policies{tree}, nil
	} else {
		return nil, err
	}
}

func (p *Policies) Get(path string) (*Policy, bool) {
	ret := new(Policy)
	foundPolicy := false
	if policy, ok := p.Tree.Get([]byte("*")); ok {
		ret.merge([]byte("*"), policy.(Policy))
		foundPolicy = true
	}

	walkFn := func(k []byte, _v interface{}) bool {
		v := _v.(Policy)
		if bytes.Equal(k, []byte(path)) || k[len(k)-1] == ':' {
			ret.merge(k, v)
			foundPolicy = true
		}

		return false
	}

	p.Tree.Root().WalkPath([]byte(path), walkFn)
	return ret, foundPolicy
}

func (p *Policies) Size() int {
	return p.Tree.Len()
}
