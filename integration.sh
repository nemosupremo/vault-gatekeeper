#!/bin/bash

set -e

function vault () {
	docker run -it --rm -e VAULT_ADDR --entrypoint=/bin/sh sjourdan/vault -c "vault auth $VAULT_TOKEN &>/dev/null; vault $*"
}

function run_tests() {

	# Run Vault
	VAULT_HOST=`docker inspect -f '{{ .NetworkSettings.IPAddress }}' vault`
	export VAULT_ADDR="http://$VAULT_HOST:8200"
	export VAULT_TOKEN=`docker logs vault 2>/dev/null | grep 'Root Token' | awk '{ printf $3 }'`

	# Import minimesos env args
	eval `minimesos info | tail -n+3`

	go test ./...
}

run_tests