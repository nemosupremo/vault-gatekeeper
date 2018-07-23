// Basic functionality for generating role secret_ids
path "auth/approle/role/*" {
	capabilities = ["create", "read"]
}

// Policy Reading (KV v2)
path "secret/data/gatekeeper" {
  capabilities = ["read"]
}
path "secret/metadata/gatekeeper/" {
  capabilities = ["list"]
}
path "secret/data/gatekeeper/*" {
  capabilities = ["read"]
}
path "secret/metadata/gatekeeper/*" {
  capabilities = ["read", "list"]
}

// Policy Reading (KV v1)
path "secret/gatekeeper" {
	capabilities = ["read"]
}
path "secret/gatekeeper/" {
  capabilities = ["list"]
}
path "secret/gatekeeper/*" {
  capabilities = ["read", "list"]
}

// When using Vault as a backing store for token usage, Gatekeeper will need
// these capabilities. (Path is the default path).
// This feature requires a v2 kv engine
path "secret/data/gatekeeper-store" {
  capabilities = ["create", "update", "read"]
}