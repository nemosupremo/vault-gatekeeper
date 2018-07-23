---
id: doc
title: Documentation
sidebar_label: Documentation
---

Vault Gatekeeper is a service for delivering Vault tokens into containers that are deployed by schedulers, such as Mesos. This tool facilitates the distribution of secrets by providing an endpoint for services to retrieve a Vault token, and checking with the container scheduler that a request for a token is valid. For example, when Mesos schedules a container on a machine, that service can check with Gatekeeper for a Vault token. Gatekeeper will then 1.) check with Mesos that the service was launched and how long it was running, 2.) check the configuration for what type of token to give it and 3.) make sure that the task hasn't requested a token already. With these three checks one can ensure that the token is being securely delivered. Gatekeeper won't allow tokens to be delivered for tasks outside the grace period, and if the token has been given already it will not deliver another one. If a token is stolen, the client application can alert operators if the token request is unexpectedly rejected.

Read more about this pattern:

* [Vault: Cubbyhole Authentication Principles](https://www.hashicorp.com/blog/vault-cubbyhole-principles.html)
* [The Secure Introduction Problem: Getting Secrets Into Containers](https://www.slideshare.net/DynamicInfraDays/containerdays-nyc-2016-the-secure-introduction-problem-getting-secrets-into-containers-jeff-mitchell)
* [Secure Credential Management on a Budget: DC/OS with HashiCorp’s Vault — Part 3](https://medium.com/mobileforgood/secure-credential-management-on-a-budget-dc-os-with-hashicorps-vault-part-3-9333c375bec0)

## Getting Started

Gatekeeper requires you have a running container scheduler, such as Mesos and Vault already running.

### 1. Gatekeeper Token

Gatekeeper will need a properly scoped Vault token in order to do its magic. When using the default configuration you can use the policy in `gatekeeper-policy.hcl` to make sure you have an appropriate policy. The easiest way to manage Gatekeeper tokens is to use [Vault AppRoles](https://www.vaultproject.io/docs/auth/approle.html). First create a `gatekeeper` policy - one is provided, using the default configuration, at the root of the repository on [GitHub](https://github.com/nemosupremo/vault-gatekeeper).

```sh
$ vault policy write gatekeeper ./gatekeeper-policy.hcl
```

Then create a `gatekeeper` AppRole. Ensure to set the `period` on the configuration so that the token can be renewed indefinitely.

```sh
$ ./vault write auth/approle/role/gatekeeper \
    secret_id_ttl=10m \
    secret_id_num_uses=1 \
    policies=gatekeeper \
    token_ttl=60m \
    period=60m
```

We will later use this AppRole to unseal Gatekeeper.

### 2. Service AppRoles

Gatekeeper leverages [Vault AppRoles](https://www.vaultproject.io/docs/auth/approle.html) to manage token configurations. You should create an AppRole for every token configuration you need for your services. In this example, we will create an AppRole for our example API service using the vault client.

```sh
$ vault write auth/approle/role/api \
    secret_id_ttl=10m \
    secret_id_num_uses=1 \
    policies=default \
    token_ttl=60m \
    period=60m
```

### 3. Policy Configuration

Next, you must store your policy configuration in Vault. Your policy configuration file is a JSON file that describes what roles a task is allowed to generate tokens for. The following a simple policy configuration for our example:

```json
{
	"mesos:marathon:api":{
		"roles":["api"],
		"num_uses":1,
	},
	"mesos:*":{
		"roles":["default"],
		"num_uses":1
	}
}
```

The keys in our JSON configuration denote the task name. For mesos, this format is `mesos:$FRAMEWORK:$TASK_NAME`. The key can end with a wildcard (`*`), which will match any task that shares the same prefix. If a task does not match *any* policy, it will be rejected.

We must then write our policy to the `policy-path` where Gatekeeper can expect to find it. The easiest way to do this is with the [Gatekeeper Cli](cli.md).

```sh
$ VAULT_TOKEN=some_token gatekeeper policy update --vault-addr http://localhost:8200 ./my-policy.json
```

We can check that policy saved correctly using the Gatekeeper Cli.

```sh
$ VAULT_TOKEN=some_token gatekeeper policy --vault-addr http://localhost:8200
{
	"mesos:marathon:api":{
		"roles":["api"],
		"num_uses":1,
	},
	"mesos:*":{
		"roles":["default"],
		"num_uses":1
	}
}
```

### 4. Start Gatekeeper

Next, we will start gatekeeper. Gatekeeper listens on port `:9201` by default.

```sh
$ gatekeeper server --schedulers mesos --vault-addr http://localhost:8200
```

Gatekeeper should start sealed by default (if it started unsealed, make sure your environment did not contain a `VAULT_TOKEN`). We can unseal it using the AppRole we created earlier using the gatekeeper cli.

```sh
$ ROLE_ID=`vault read --field role_id auth/approle/role/gatekeeper/role-id`
$ SECRET_ID=`vault write -f --field secret_id auth/approle/role/gatekeeper/secret-id`
$ gatekeeper unseal approle --auth-app-role $ROLE_ID --auth-app-secret $SECRET_ID
INFO[2018-07-21T19:01:07-07:00] Unsealing gatekeeper at http://localhost:9201
INFO[2018-07-21T19:01:07-07:00] Unsealed.
```

Now Gatekeeper is running and ready to start serving requests. You can test gatekeeper by launching a simple script on Marathon with the id `api`.

```sh
$ curl -X POST -d"{\"task_id\":\"${MESOS_TASK_ID}\"}" 'http://gatekeeper-host/token'
```

This should deliver a response wrapped token, that you will then have to unwrap to get your actual token.

## Configuration

Gatekeeper server can be started by running the `server` command. For example `gatekeeper server` or `docker run nemosupremo/vault-gatekeeper server`.

The section will cover configuring the Gatekeeper server. Gatekeeper can be configured with command line options, or environment variables. The environment variables are named the same as the command line options, except they are all UPPERCASE and the dashes (`-`) will become underscores (`_`).

### HTTP Configuration

#### `--listen-addr`
*default `:9201`*

#### `--tls-cert`

Path to a HTTP certificate. Setting this option will enable TLS.

#### `--tls-key`

Path to a HTTP private key. Setting this option will enable TLS.

### Scheduler Providers

#### `--schedulers`
*default: `mesos`*

A comma separated list of scheduler backend providers. Can include `mesos` or `ecs`.

#### `--mesos-master`

URI to the mesos masters. Multiple hosts can be specified by comma separating the hosts in the URI. A zookeeper path can also be specified with `zk` or `zks` as the protocol, and the path as the zookeeper path.

Ex.
* `http://leader.mesos:5050`
* `https://master01.infra:5050,master02.infra:5050,master03.infra:5050`
* `zk://zoo01.infra:5050,zoo02.infra:5050,zoo03.infra:5050/mesos`

#### `--host-check`
*default: `false`*

When enabled, Gatekeeper will check that the remote address of the http request requesting the token is the same address as the agent running the task. this ensures that requests for tokens can only originate from servers that are running the container.

#### `--use-image-name`
*default: `false`*

Instead of using the image's name in the policy (for example, using the Marathon App ID), the Docker image will be used. This allows you to specify your policy based on the docker image running.

### Vault

#### `--vault-addr`
*default: `http://127.0.0.1:8200/`*

Address of the Vault server expressed as a URL and port, for example: `https://127.0.0.1:8200/`.

#### `--vault-cacert`

Path to a PEM-encoded CA certificate file on the local disk. This file is used to verify the Vault server's SSL certificate. This environment variable takes precedence over VAULT_CAPATH.

#### `--vault-capath`

Path to a directory of PEM-encoded CA certificate files on the local disk. These certificates are used to verify the Vault server's SSL certificate.

#### `--vault-client-cert`

Path to a PEM-encoded client certificate on the local disk. This file is used for TLS communication with the Vault server.

#### `--vault-client-key`

Path to an unencrypted, PEM-encoded private key on disk which corresponds to the matching client certificate.

#### `--vault-skip-verify`
*default: `false`*

Do not verify Vault's presented certificate before communicating with it.

#### `--vault-kv-version`
*default: `2`*

The KV engine version for secrets mounted on the Gatekeeper policy path. Either `1` or 	`2`

#### `--vault-approle-mount`
*default: `approle`*

The path name where the `approle` auth backend is mounted.

### Policy

#### `--task-grace`
*default: `2m`*

The task grace period after a task is started where it can request for a Vault Token. Tasks that have been active longer than this period will no longer be able to request tokens.

#### `--policy-path`
*default: `secret/data/gatekeeper`*

Path to a kv mounted secret engine path, on the Vault server, where the policies are stored. The token that is used to unseal Gatekeeper must have permissions to read *and* list these paths.

### Unsealing

Unsealing options can be provided to Gatekeeper at launch so that it starts up unsealed.

#### `--vault-token`

Unseals Gatekeeper with the provided Vault Token.

#### `--auth-token-wrapped`

Unseals Gatekeeper with a response wrapped token. Gatekeeper will unwrap this token using `sys/wrapping/unwrap` and expects the final token there.

#### `--auth-app-role`, `--auth-app-secret`

Unseals Gatekeeper with an AppRole. Specify the `role_id` and `secret_id`.

#### `--auth-aws-ec2`, `--auth-aws-nonce`

Unseals Gatekeeper with the AWS auth ec2 method. Optionally specify a nonce for repeated authentications. See the [Vault AWS Auth](https://www.vaultproject.io/docs/auth/aws.html) docs for more details.

#### `--auth-aws-iam`

Unseals Gatekeeper with the AWS auth iam method.

### High Availability

#### `--usage-store`
*default: `memory`*

Usage store must be one of `memory` or `vault`. To enable high availability, you must use a strongly consistent store. The store is where Gatekeeper stores information about tasks it has already given tokens to.

#### `--usage-store-vault-path`
*default: `secret/data/gatekeeper-store`*

Path to a key, that gatekeeper can access and update to store information about used tokens on the Vault usage store backend. Should not be under `--policy-path` and must be mounted a v2 kv store.

#### `--peers`

A comma separated list of Gatekeeper URIs to use as peers. Gatekeeper will forward requests to unsealed peers if the instance is currently sealed. Gatekeeper will resolve the hostname provided here and treat all the IPs that resolve to that hostname as peers.

__Note:__ This option will fail if `--usage-store` is set to `memory`.

__Note:__ Even in HA mode, all gatekeeper instances must be unsealed individually.


### Metrics

#### `--metrics-ticker`
*default: `10s`*

Sets how often gauge statistics will be reported.

#### `--metrics-statsd`

Set to a hostname and port of a statsd instance to enable metrics reporting over statsd.

#### `--metrics-statsd-prefix`
*default: `gatekeeper`*

Sets the statsd prefix.

#### `--metrics-statsd-influx`

If set, enables the use of Influx DB tags on the statsd reporter.

#### `--metrics-statsd-datadog`

If set, enables the use of DataDog tags on the statsd reporter.

## Policies

Policies define what tasks will be given what roles if any. The policy configuration is JSON is stored in your Vault instance where it is loaded by Gatekeeper when it is unsealed. You can reload the policies loaded in Gatekeeper at anytime using the `policies/reload` API call or `policy reload` CLI command.

Each policy object has two parameters

#### `roles`

Roles is a list of [AppRole](https://www.vaultproject.io/docs/auth/approle.html) role names that a task can use. If a task does not specify an AppRole, the first role in the list is used. There are also templated a AppRoles - `{{name}}`. This special AppRole name resolves to the task name as defined in the backend.

#### `num_uses`

The `num_uses` option specifies how many times a task can request a token. This value reflects how many times a legitimate service should request a token from Gatekeeper - in most deployments this is almost always 1. This value must be defined and must be greater than 0.

### Schema

```js
{
	"{scheduler}:{scheduler_group}:{task_name}":{
		"roles":[""], // string array
		"num_uses":1 // number of times a single task id can request a token. Must be greater than 0.
	},
	// if `--use-image-name` is enabled
	"{scheduler}:{docker_image}:{image_tag}":{
		"roles":[""],
		"num_uses":1
	},
	// catch all expression
	"*":{...},
	// glob expressions, wildcard must be at the end
	"mesos:marathon:*":{...},
	"ecs:*":{...}
	"mesos:hashicorp/terraform:*"
}
```

#### Key Names

The key names define are used to match a task to a policy. They can either be fully defined in the format `{scheduler}:{scheduler_group}:{task_name}` for schedulers that support groups (ex. with the `mesos` scheduler, the `scheduler_group` will be the framework name.) or `{scheduler}:{task_name}` for schedulers that don't support groups. If `--use-image-name` is enabled the format must be `{scheduler}:{docker_image}:{image_tag}`. The names can also support glob-style matching at the end of the key, which will match all task names sharing that prefix.

### Nesting

Policies can be separated into seperate keys under the `policy-path`. For example, for servers and applications where one set of policies may be saved to `/v1/secret/gatekeeper/frontend` and the another could be saved to `/v1/secret/gatekeeper/backend`. Gatekeeper will merge these policies and any of their children. Policies paths are merged in such a way that the entire directories are walked in alphabetical order.