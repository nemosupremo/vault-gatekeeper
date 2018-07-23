vault-gatekeeper
=========

[![Build Status](https://travis-ci.org/nemosupremo/vault-gatekeeper.svg?branch=master)](https://travis-ci.org/nemosupremo/vault-gatekeeper)

Vault-Gatekeeper is a small service for delivering [Vault](https://www.vaultproject.io/) token
to other services who's lifecycles are managed by a container scheduler such as [Mesos](https://mesos.apache.org) or [ECS](https://aws.amazon.com/ecs/).

Vault-Gatekeeper takes the Cubbyhole Authenication approach outlined by Jeff Mitchell on [Vault Blog](https://www.hashicorp.com/blog/vault-cubbyhole-principles.html). Specifically Vault response wrapping is used as outlined in the [Vault documentation](https://www.vaultproject.io/docs/concepts/response-wrapping.html).

In short, a service will request a vault token from VG supplying its Mesos task id or ECS task arn. VG will then check with Mesos/ECS to
ensure that the task has been recently started and that VG has not already issued a token for that task id. Then VG will check its configuration to understand what role that task is assigned and request a response wrapped token from Vault. VG will then pass the token to the service which can then unwrap the response with `/sys/wrapping/unwrap` to retrieve the token.

## Requirements

* Vault 0.6.2+
* Mesos 1.0.0+ (*if using Mesos*)

## Documentation

Visit [http://nemosupremo.github.io/vault-gatekeeper](http://nemosupremo.github.io/vault-gatekeeper)

## Quickstart

This guide assumes that you 1.) have a Vault instance running, 2.) have a Mesos instance running and 3.) have an approle policy in Vault named `test`.

1. Install a sample policy in Vault
```sh
$ echo '{"mesos:*":{"roles":["test"],"num_uses":1}}' | ./gatekeeper policy update --vault-token 'MY_TOKEN' '-'
```
2. Start a Gatekeeper instance
```sh
$ ./gatekeeper server --mesos-master 'http://leader.mesos:5050' --vault-addr http://localhost:8200
```
3. Unseal the Gatekeeper instance with a token. (The token must have at least the policy defined in `gatekeeper-policy.hcl`).
```sh
$ ./gatekeeper unseal token --vault-token 'GK_TOKEN'
```
4. Launch a task on mesos and retrieve a token:
```sh
$ curl -X POST -d"{\"task_id\":\"${MESOS_TASK_ID}\"}" 'http://gatekeeper-host/token'
```

## Downloading

You can grab a binary from the releases or deploy the docker image [nemosupremo/vault-gatekeeper](https://hub.docker.com/r/nemosupremo/vault-gatekeeper/).

## License

[MIT](http://opensource.org/licenses/MIT)
