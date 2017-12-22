vault-gatekeeper-mesos
=========

[![Build Status](https://travis-ci.org/ChannelMeter/vault-gatekeeper-mesos.svg?branch=master)](https://travis-ci.org/ChannelMeter/vault-gatekeeper-mesos)

Vault-Gatekeeper-Mesos (VGM) is a small service for delivering [Vault](https://www.vaultproject.io/) token
to other services who's lifecycles are managed by [Mesos](https://mesos.apache.org) or one of it's frameworks
(such as [Marathon](https://mesosphere.github.io/marathon/)), or [ECS](https://aws.amazon.com/ecs/).

VGM takes the Cubbyhole Authenication approach outlined by Jeff Mitchell on [Vault Blog](https://www.hashicorp.com/blog/vault-cubbyhole-principles.html).
Specifically Vault response wrapping is used as outlined in the [Vault documentation](https://www.vaultproject.io/docs/concepts/response-wrapping.html).
In short, a service will request a vault token from VGM supplying its Mesos task id or ECS task arn. VGM will then check with Mesos/ECS to 
ensure that the task has been recently started and that VGM has not already issued a token for that task id. If so, 
VGM requests the creation of a response-wrapped token. Behind the scenes, Vault creates 2 tokens 
(`temp` and `perm`). The `temp` token, which can only be used twice, will be first used
by Vault internally to write the `perm` token into it's own Cubbyhole at the path `response`. This `temp` token is then provided to the service, which
can use that token to retrieve the `perm` token by making a PUT request to Vault at `/sys/wrapping/unwrap` with
the `temp` token as the value of the `X-Vault-Token` header. 

VGM can also ensure the correct policies are set on the `perm` token by using an internal configuration
based on the task's name in Mesos/ECS.

**Requires Vault 0.6.0 or greater**

## Deploying

You can grab a binary from the releases or deploy the docker image [channelmeter/vault-gatekeeper-mesos](https://hub.docker.com/r/channelmeter/vault-gatekeeper-mesos/). When deploying VGM
you must consider how you will deliver it's Vault authorization token. To issue a token to VGM on startup you can use
the `VAULT_TOKEN`, `AWS_EC2_LOGIN` or `APP_ID` (and accompayning `USER_ID_*`) environment variables. Otherwise VGM functions like Vault
in that it starts "sealed" and it must be "unsealed". It can be unsealed via JSON API, or you can direct your browser
to http://gate.keep.er:9201 and use the UI provided there.

VGM also supports the client environment variables used by vault such as, `VAULT_ADDR`, `VAULT_SKIP_VERIFY`,
`VAULT_CACERT` and `VAULT_CAPATH`.

## Arguments

`LISTEN_ADDR` | `-listen` - *Default: `:9201`* - The address this service should listen on.

`TLS_CERT` | `-tls-cert` - Path to TLS certificate. If this value is set, gatekeeper will be served over TLS.

`TLS_KEY` | `-tls-key` - Path to TLS key. If this value is set, gatekeeper will be served over TLS.

`PROVIDER` | `-provider` - Configures the underlying Docker environment provider.  Currently supports `mesos` (default), `ecs` and `test` (Test provider should only be used during testing)

`MESOS_MASTER` | `-mesos` - The address of the mesos master. Can be either a zookeeper link (`zk://zoo1:2181,zoo2:2181/mesos`) or a http link to a single or multiple mesos masters (`http://leader.mesos:5050`).

`VAULT_ADDR` | `-vault` - The address of the vault server.

`VAULT_SKIP_VERIFY` | `tls-skip-verify` - Do not verify TLS certificate.

`VAULT_CACERT` | `-ca-cert` -  Path to a PEM encoded CA cert file to use to verify the Vault server SSL certificate.

`VAULT_CAPATH` | `-ca-path` -  Path to a directory of PEM encoded CA cert files to verify the Vault server SSL certificate.

`GATE_POLICIES` | `-policies` - *Default: `/gatekeeper`* The path on the `generic` vault backend to load policies from (See Policies section). The initial `/secret` path segment should not be included.

`GATE_POLICIES_NESTED` | `-policies-nested` - *Default: `false`* - Option to load nested policies from sub directories starting at the path specified by GATE_POLICIES. 

`TASK_LIFE` | `-task-life` - *Default: `2m`* - The maximum age of a task before VGM will refuse to issue tokens for it.

`RECREATE_TOKEN` | `-self-recreate-token` - *Default: `false`* - When the current token is reaching it's MAX_TTL (720h by default), recreate the token with the same policy instead of trying to renew (requires a sudo/root token, and for the token to have a ttl).

`SEAL_HTTP_STATUS` | `-seal-http-status` - *Default: `200`* - Configures HTTP Status Code to be returned when querying /status.json.  By default uses 200 in both cases, but can be configured to return 429, for example, if the status is sealed.

### Vault Startup Authorization Methods

`VAULT_TOKEN` - Vault authorization token to make requests with.

`CUBBY_TOKEN` | `-cubby-token` - Temporary vault authorization token that has a cubbyhole secret in `CUBBY_PATH` that contains the permanent vault token.

`CUBBY_PATH` | `-cubby-path` - Path to key in cubbyhole. By default this is `/vault-token`.

`WRAPPED_TOKEN_AUTH` | `-wrapped-token-auth` - Temporary vault authorization token that has a wrapped permanent vault token.

`APP_ID` | `-auth-appid` - Use the `app-id` authorization method with this app id.

`USER_ID_METHOD` | `-auth-userid-method` - With the `app-id` authorization method, this argument decides how VGM should generate the user id. Valid values are `mac` and `file`.

`USER_ID_INTERFACE` | `-auth-userid-interface` - When `USER_ID_METHOD` is `mac`, this is the name of the interface that the mac address should be generated from.

`USER_ID_PATH` | `-auth-userid-path` - When `USER_ID_METHOD` is `file`, read the data from this file as the `user_id`.

`USER_ID_HASH` | `-auth-userid-hash` - Hash the `user_id` with this scheme. Valid values are `sha256`, `sha1`, and `md5`.

`USER_ID_SALT` | `-auth-userid-salt` - When provided, the `user_id` will be hashed with `salt$user_id`.

`AWS_EC2_LOGIN` | `-auth-aws-ec2` - When set to `true`, will use `aws-ec2` authorization method with `pkcs7` image signature

`AWS_ROLE` | `-auth-aws-ec2-role` - When provided, the `role` will be sent to Vault as part of the `aws-ec2` authorization
 
`AWS_NONCE` | `-auth-aws-ec2-nonce` - When provided, the `nonce` will be sent to Vault as part of the `aws-ec2` authorization

## Unsealing

By default, VGM, like Vault, will start sealed. The `APP_ID`, `AWS_EC2_LOGIN` and `VAULT_TOKEN` arguments can be started with VGM in order to start unsealed.

While VGM is sealed there are two ways to unseal it, via the API or with your browser (by just opening the url VGM is listening on). 
See the _`POST` **/unseal**_ section for information on the different unseal methods.

You may wish to supply VGM with a token whose permissions are narrowly restricted. The token needs at least the following permissions:

     # This will give VGM permission to create tokens with any subset of policies of its own token.
     path "auth/token/create" {
        capabilities = ["create","update","sudo"]
     }
	 
	 # Needed for VGM unsealing
     path "auth/token/lookup*" {
         capabilities = ["read"]
     }

	 # Needed so that VGM can unseal its token
     path "auth/token/renew-self" {
         capabilities = ["create","update"]
     }

	 # This is whatever path you set GATE_POLICIES to (but with the initial secret/ path segment).
     path "secret/vault_gatekeeper_mesos" {
         capabilities = ["read"]
	 }

In addition, the VGM token should have the policies that it is creating tokens for; i.e., if an application needs
read permission to `secret/my_application/foo` then the VGM token should also have that policy, since its token
can only create tokens with a subset of its own policies.

## Policies


VGM will create tokens with given policies by using the data in its `policies` config. This config is pulled from vault, whose path is determined by a combination of a `generic` backend,
which defaults to `secret`, and a key provided by you. For example, if you provide a policy path of `/gatekeeper-policy`, this translates to `/secret/gatekeeper-policy` in vault.
A `policies` config is a simple json structure, with the key name being the Mesos task name (with the Marathon framework this is your app name), or ECS Task Definition name part of the ARN, and the value being select
token options. Policy names support glob-style matching, with the longest pattern taking priority.


#### Token Options
`policies` (list, optional, default: default policy) - A list of policies to attach to the provided vault token

`meta` (dict, optional) - Token metadata

`ttl` (int, optional) - TTL of the provided token

`num_uses` (int, optional) - Number of time a token can be used. 0 is translated to no limit

`multi_fetch` (bool, optional, default: false) - Allows a task to request multiple tokens before it reaches its maximum task life. This is useful for a single task that contain multiple processes, each which require their own token

`multi_fetch_limit` (int) - If `multi_fetch` is true, this value specifies how many times a task can obtain a token


### Example policy config

```json
{
	"app-server":{
		"policies":["app"],
		"meta":{"foo":"bar"},
		"multi_fetch":true,
		"multi_fetch_limit":10,
		"ttl":3000,
		"num_uses":0
	},
	"web-server":{
		"policies":["web"],
		"meta":{"foo":"bar"},
		"ttl":3000,
		"num_uses":0
	},
	"ChronosTask:my_special_task":{
		"policies":["special_task"],
		"meta":{"foo":"bar"},
		"ttl":3000,
		"num_uses":0
	},
	"ChronosTask:*":{
		"policies":["batch"],
		"meta":{"foo":"bar"},
		"ttl":3000,
		"num_uses":0
	},
	"*":{
		"policies":["default"],
		"ttl":1500
	}
}
```

In the above, any task starting with `ChronosTask:` will get the `batch` policy except `ChronosTask:my_special_task`, which will get `special_task`.

You will have to use the Vault API in order to set the policies to your backend. Assuming your policy is saved as `policy.json`, here's how to save that information using cURL.

```bash
$ curl -X POST -H "X-Vault-Token: <MY TOKEN>" -H "Content-Type: application/json" -d @policy.json http://vault/v1/secret/gatekeeper
```

If you update the policy secret, you will need to restart VGM or reload the policies via the `/policies/reload` API (see below) to apply the changes.

#### Optional nested policies
An option to keeping all the policies in a single json file is to organize the policies into nested groups. The policies can be broken into separate config json files and stored in vault to policy paths that are sub directories to the path specified in the Argument GATE_POLICIES. 
This option can be activated by setting the Argument GATE_POLICIES_NESTED to True. This option can help when different groups manage their own policies or when there are a large number of policies.  

For example, the policies listed in the Example policy config above, could be separated by servers and applications where "app-server" and "web-server" 
could be posted to /v1/secret/gatekeeper/servers and the two Chronos policies could be posted to /v1/secret/gatekeeper/chronos. The global policy * in the example could remain in its own json file that could still be posted to 
/v1/secret/gatekeeper. Multiple levels of nesting is supported.  

#### Example nested policy configs
##### server json
```json
{
	"app-server":{
		"policies":["app"],
		"meta":{"foo":"bar"},
		"multi_fetch":true,
		"multi_fetch_limit":10,
		"ttl":3000,
		"num_uses":0
	},
	"web-server":{
		"policies":["web"],
		"meta":{"foo":"bar"},
		"ttl":3000,
		"num_uses":0
	}
}
```
##### chronos json
```json
{
	"ChronosTask:my_special_task":{
		"policies":["special_task"],
		"meta":{"foo":"bar"},
		"ttl":3000,
		"num_uses":0
	},
	"ChronosTask:*":{
		"policies":["batch"],
		"meta":{"foo":"bar"},
		"ttl":3000,
		"num_uses":0
	}
}
```
##### policy json
```json
{
	"*":{
		"policies":["default"],
		"ttl":1500
	}
}
```

The organization of the policies does not impact gatekeeper internally since all the nested policies are loaded into a single list when they are initially loaded during an "unseal" or when reloaded (see policies/reload  API).

Note: When loading using the nested policies option, and duplicate key names will be logged and then skipped. When not using nested policies, the original logic will overwrite the policy if a duplicate is encountered.

The cURL example above would now need two additional POSTs for the new json files and paths:

```bash
... -d @servers.json http://vault/v1/secret/gatekeeper/servers
... -d @chronos.json http://vault/v1/secret/gatekeeper/chronos
```


## API

#### `GET` **/status.json**

Gets the status of VGM.

Response -

```json
{
	"ok":true,
	"started":"time VGM was started",
	"status":"Either Sealed or Unsealed",
	"uptime":"Duration of uptime",
	"stats":{
		"requests":"number of token requests",
		"successful":"number of successful requests",
		"denied":"number of denied requests"
	}
}
```

#### `POST` **/seal**

Seal the service. The token that was provided will be forgotten.

Response -

```json
{
	"ok":true,
	"status":"Either Sealed or Unsealed",
	"error":"error if any"
}
```

#### `POST` **/unseal**

Unseal the service.

Parameters (`application/json`) -
* `type` - One of `wrapped-token`,`token`, `userpass`, `app-id`, `github`, `cubby`, `aws`
* `token` - Vault Authorization token if `type` is `token`, wrapped token if `type` is `wrapped-token`, Github Personal token if `type` is `github`, temp token with `{"token":"perm_token"}` in `cubby_path` if `type` is `cubby`.
* `cubby_path` - The path in `v1/cubbyhole/` when using `cubby` authorization. Default will be `/vault-token`.
* `username` - Username for `userpass` authenication.
* `password` - Password for `userpass` authenication.
* `app_id` - See `APP_ID` in *Vault Startup Authorization Methods*
* `user_id_method` - See `USER_ID_METHOD` in *Vault Startup Authorization Methods*
* `user_id_interface` - See `USER_ID_INTERFACE` in *Vault Startup Authorization Methods*
* `user_id_path` - See `USER_ID_PATH` in *Vault Startup Authorization Methods*
* `user_id_hash` - See `USER_ID_HASH` in *Vault Startup Authorization Methods*
* `user_id_salt` - See `USER_ID_SALT` in *Vault Startup Authorization Methods*
* `aws_role` - See `AWS_ROLE` in *Vault Startup Authorization Methods*
* `aws_nonce` - See `AWS_NONCE` in *Vault Startup Authorization Methods*

Response -

```json
{
	"ok":true,
	"status":"Either Sealed or Unsealed",
	"error":"error if any"
}
```

#### `POST` **/policies/reload**

Reload the gatekeeper policies from the Vault secret path (`GATE_POLICIES` | `-policies`). Do this after updating the policy secret in the Vault.

Response -

```json
{
	"ok":true,
	"status":"Either Sealed or Unsealed",
	"error":"error if any"
}
```

#### `POST` **/token**

Request a token.

Parameters (`application/json`) -
* `task_id` - The Mesos Task ID or ECS Task ARN of the service. The Mesos Task Id is exported by Mesos to container environments in the environment variable `MESOS_TASK_ID`.

Response -

```json
{
	"ok":true,
	"status":"Either Sealed or Unsealed",
	"token":"temp cubbyhole token",
	"error":"error if any"
}
```

## Sample

Here is a simple program that gets a vault token.

```go
package main

import (
	"fmt"
	"github.com/channelmeter/vault-gatekeeper-mesos/gatekeeper"
)

func main() {
	// Mesos 
	token, err := gatekeeper.RequestVaultToken("geard.3d151450-1092-11e6-8d2c-00163e105043")
	fmt.Printf("%v %v\n", token, err)
	// ECS 
	token, err = gatekeeper.RequestVaultToken("arn:aws:ecs:us-west-1:123456789012:task/4d98b71d-5d86-4d09-a01d-f2e7b8dd7bd1")
	fmt.Printf("%v %v\n", token, err)
}
```
