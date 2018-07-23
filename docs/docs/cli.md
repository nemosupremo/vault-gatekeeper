---
id: cli
title: CLI Documentation
---

## server

See the [Configuration Documentation](doc.md#configuration)

## seal
Seals the Gatekeeper instance

```
Usage:
  gatekeeper seal [flags]

Flags:
      --gatekeeper-addr string   Hostname address of the gatekeeper instance. (default "http://localhost:9201")
  -h, --help                     help for seal
```

## unseal
Unseals the gatekeeper instance. The available methods are:

* token
* token-wrapped
* approle
* aws
* github

```
Usage:
  gatekeeper unseal [method] [flags]

Flags:
      --gatekeeper-addr string      The address to gatekeeper. (default "http://localhost:9201")
      --vault-token string          Unseal gatekeeper at startup with a Vault token.
      --auth-token-wrapped string   Unseal gatekeeper at startup with a Vault token that is stored with a response wrapped temp token.
      --auth-app-role string        Unseal gatekeeper at startup with a Vault token retrieved using this app role.
      --auth-app-secret string      The app role secret_id to be used.
      --auth-aws-ec2                Unseal gatekeeper at startup using EC2 login.
      --auth-aws-iam string         Unseal gatekeeper at startup using IAM login.
      --auth-aws-nonce string       AWS-EC2 nonce for repeated authentication.
      --auth-gh-token string        Vault authorized github personal token.
  -h, --help                        help for unseal
```


## policy

View the current gatekeeper policy file.

```
Usage:
  gatekeeper policy [command] [flags]
  gatekeeper policy [command]

Available Commands:
  reload      Reload the gatekeeper policy on an instance.
  update      Update the current gatekeeper policy file from a file. Specify '-' to read from stdin.

Flags:
      --vault-addr string           The address to the vault server. (default "http://localhost:8200")
      --vault-client-cert string    Path to a PEM-encoded client certificate on the local disk. This file is used for TLS communication with the Vault server. (This is different from the TLS Certificates Auth Method).
      --vault-client-key string     Path to an unencrypted, PEM-encoded private key on disk which corresponds to the matching client certificate. (This is different from the TLS Certificates Auth Method).
      --vault-skip-verify           Skip TLS verification of Vault's SSL certificate.
      --vault-kv-version string     Vault KV backend version that is used for the policy-path. Either v1 or v2. (default "2")
      --policy-path string          The path on Vault to a v2 kv backend where gatekeeper can load the token policy. Gatekeeper will merge all policies at this path and its children's paths. (default "secret/data/gatekeeper")
      --vault-token string          Unseal gatekeeper at startup with a Vault token.
      --auth-token-wrapped string   Unseal gatekeeper at startup with a Vault token that is stored with a response wrapped temp token.
      --auth-app-role string        Unseal gatekeeper at startup with a Vault token retrieved using this app role.
      --auth-app-secret string      The app role secret_id to be used.
      --auth-aws-ec2                Unseal gatekeeper at startup using EC2 login.
      --auth-aws-iam string         Unseal gatekeeper at startup using IAM login.
      --auth-aws-nonce string       AWS-EC2 nonce for repeated authentication.
      --auth-gh-token string        Vault authorized github personal token.
  -h, --help                        help for policy
```

## policy update

Update the current gatekeeper policy file from a file. Specify `-` to read from stdin.

```
Usage:
  gatekeeper policy update [file] [flags]

Flags:
  -h, --help   help for update

Global Flags:
      --auth-app-role string        Unseal gatekeeper at startup with a Vault token retrieved using this app role.
      --auth-app-secret string      The app role secret_id to be used.
      --auth-aws-ec2                Unseal gatekeeper at startup using EC2 login.
      --auth-aws-iam string         Unseal gatekeeper at startup using IAM login.
      --auth-aws-nonce string       AWS-EC2 nonce for repeated authentication.
      --auth-gh-token string        Vault authorized github personal token.
      --auth-token-wrapped string   Unseal gatekeeper at startup with a Vault token that is stored with a response wrapped temp token.
      --policy-path string          The path on Vault to a v2 kv backend where gatekeeper can load the token policy. Gatekeeper will merge all policies at this path and its children's paths. (default "secret/data/gatekeeper")
      --vault-addr string           The address to the vault server. (default "http://localhost:8200")
      --vault-client-cert string    Path to a PEM-encoded client certificate on the local disk. This file is used for TLS communication with the Vault server. (This is different from the TLS Certificates Auth Method).
      --vault-client-key string     Path to an unencrypted, PEM-encoded private key on disk which corresponds to the matching client certificate. (This is different from the TLS Certificates Auth Method).
      --vault-kv-version string     Vault KV backend version that is used for the policy-path. Either v1 or v2. (default "2")
      --vault-skip-verify           Skip TLS verification of Vault's SSL certificate.
      --vault-token string          Unseal gatekeeper at startup with a Vault token.
```

## policy reload
Reload the gatekeeper policy on an instance.

```
Usage:
  gatekeeper policy reload [flags]

Flags:
  -h, --help   help for reload

Global Flags:
      --gatekeeper-addr string      The address to gatekeeper. (default "http://localhost:9201")
```