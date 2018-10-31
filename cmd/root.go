package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nemosupremo/vault-gatekeeper/scheduler"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const defaultVaultAddr = "http://localhost:8200"
const defaultGatekeeperAddr = "http://localhost:9201"
const defaultPolicyPath = "secret/data/gatekeeper"
const defaultVaultKvVer = "2"

var Version = "dev"

func init() {
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	viper.SetDefault("log-level", "info")

	rootCmd.PersistentFlags().String("log-level", viper.GetString("log-level"), "Logging level.")

	viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))
}

func bindViperFlags(cmd *cobra.Command, options []scheduler.Args) {
	for _, option := range options {
		viper.BindPFlag(option.Name, cmd.PersistentFlags().Lookup(option.Name))
	}
}

var rootCmd = &cobra.Command{
	Use:              "gatekeeper [command]",
	Short:            "",
	PersistentPreRun: Setup,
}

var RootCmd = rootCmd

func Setup(cmd *cobra.Command, args []string) {
	if l, err := logrus.ParseLevel(viper.GetString("log-level")); err == nil {
		logrus.SetLevel(l)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	logrus.SetFormatter(&logrus.TextFormatter{TimestampFormat: time.RFC3339, FullTimestamp: true})
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
