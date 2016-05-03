package main

import (
	"fmt"
	"github.com/channelmeter/vault-gatekeeper-mesos/gatekeeper"
)

func main() {
	token, err := gatekeeper.RequestVaultToken("geard.3d151450-1092-11e6-8d2c-00163e105043")
	fmt.Printf("%v %v\n", token, err)
}
