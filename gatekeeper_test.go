package main

import (
	"os"
)

var (
	flagVaultAddr    = flag.String("vault", os.Getenv("VAULT_ADDR"), "Vault Address")
	flagMesosAddr    = flag.String("mesos", os.Getenv("MINIMESOS_MASTER"), "Mesos Master Address")
	flagMarathonAddr = flag.String("marathon", os.Getenv("MINIMESOS_MARATHON"), "Marathon Address")
	flagZkAddr       = flag.String("zk", os.Getenv("MINIMESOS_ZOOKEEPER"), "Zookeeper Address")

	flagCassVersion cassVersion
	clusterHosts    []string
)
