#!/bin/bash

set -e

function vault () {
	docker run -it --rm -e VAULT_ADDR --entrypoint=/bin/sh vault -c "vault auth $VAULT_TOKEN &>/dev/null; vault $*"
}

function run_tests() {

	# Run Vault
	VAULT_HOST=`docker inspect -f '{{ .NetworkSettings.IPAddress }}' vault`
	export VAULT_ADDR="http://${VAULT_HOST}:8200"
	export VAULT_TOKEN="vault-gatekeeper-test-token-id"

	# Import minimesos env args
	# TODO: reenable
	# eval `minimesos info | tail -n+3`

	# wait for vault to startup
	sleep 5
	vault auth-enable userpass
	go test -v ./
}

run_tests