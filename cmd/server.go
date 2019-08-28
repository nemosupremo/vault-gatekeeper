package cmd

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/packetloop/vault-gatekeeper"
	"github.com/nemosupremo/vault-gatekeeper/scheduler"
	"github.com/nemosupremo/vault-gatekeeper/vault/unsealer"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serverOptions []scheduler.Args

func init() {
	serverCmd.Flags().SortFlags = false
	serverCmd.PersistentFlags().SortFlags = false
	options := []scheduler.Args{
		{"listen-addr", ":9201", "Listen address that gatekeeper should listen on."},
		{"schedulers", "mesos", "Comma seperated list of schedulers to enable. The first one will be the default if no specific one is requested."},
		{"host-check", false, "Check that the remote address of the service requesting for a token matches the address of the agent that the task runs on."},
		{"use-image-name", false, "Use the Docker image name, rather than the task name for verifying token policies."},
		{"tls-cert", "", "Path to a TLS Certificate. When specified, gatekeeper will only serve requests over TLS."},
		{"tls-key", "", "Path to a TLS Key. When specified, gatekeeper will only serve requests over TLS."},
		{"peers", "", "Comma seperated of gatekeeper peers for high availability mode. Gatekeeper will attempt to reload coordinate policy reloads and send token requests to these nodes if this node is sealed."},

		{"vault-addr", defaultVaultAddr, "The address to the vault server."},
		{"vault-cacert", "", "Path to a PEM-encoded CA certificate file on the local disk. This file is used to verify the Vault server's SSL certificate. This environment variable takes precedence over VAULT_CAPATH."},
		{"vault-capath", "", "Path to a directory of PEM-encoded CA certificate files on the local disk. These certificates are used to verify the Vault server's SSL certificate."},
		{"vault-client-cert", "", "Path to a PEM-encoded client certificate on the local disk. This file is used for TLS communication with the Vault server. (This is different from the TLS Certificates Auth Method)."},
		{"vault-client-key", "", "Path to an unencrypted, PEM-encoded private key on disk which corresponds to the matching client certificate. (This is different from the TLS Certificates Auth Method)."},
		{"vault-skip-verify", false, "Skip TLS verification of Vault's SSL certificate."},
		{"vault-kv-version", defaultVaultKvVer, "Vault KV backend version that is used for the policy-path. Either '1' or '2'."},
		{"vault-approle-mount", "approle", "Vault AppRole mount in your configuration."},

		{"task-grace", 2 * time.Minute, "Task grace period, during which a task can request a token. If a task attempts to ask for a token after this period, it will be rejected."},
		{"policy-path", defaultPolicyPath, "The path on Vault to a kv backend where gatekeeper can load the token policy. Gatekeeper will merge all policies at this path and its children's paths."},

		{"usage-store", "memory", "Usage state store used by gatekeeper to \"remember\" which tasks have already been given tokens."},
		{"usage-store-vault-path", "secret/data/gatekeeper-store", "Path to a key, that gatekeeper can access and update to store information about used tokens on the Vault usage store backend. Should not be under --policy-path and must be mounted a v2 kv store."},

		{"vault-token", "", "Unseal gatekeeper at startup with a Vault token."},
		{"auth-token-wrapped", "", "Unseal gatekeeper at startup with a Vault token that is stored with a response wrapped temp token."},

		{"auth-app-role", "", "Unseal gatekeeper at startup with a Vault token retrieved using this app role_id."},
		{"auth-app-secret", "", "The app role secret_id to be used."},

		{"auth-aws-ec2", false, "Unseal gatekeeper at startup using EC2 login."},
		{"auth-aws-iam", "", "Unseal gatekeeper at startup using IAM login."},
		{"auth-aws-nonce", "", "AWS-EC2 nonce for repeated authentication."},

		{"metrics-ticker", 10 * time.Second, "How often to report gauge statistics to the backend."},
		{"metrics-statsd", "", "Report metrics to a statsd server."},
		{"metrics-statsd-prefix", "gatekeeper", "StatsD prefix."},
		{"metrics-statsd-influx", false, "Enable influxdb tags."},
		{"metrics-statsd-datadog", false, "Enable datadog tags."},

		{"local-dev-mode", false, "Bypass any scheduler check to intended for local development. Not recommended for production use."},
		{"vault-public-addr", defaultVaultAddr, "Return a public Vault address for client to connect to. Intended for Vault cluster in private network and connection via proxy."},
	}

	options = append(options, scheduler.AllArgs()...)
	serverOptions = options
	for _, option := range options {
		viper.SetDefault(option.Name, option.Default)
	}

	for _, option := range options {
		switch option.Default.(type) {
		case string:
			serverCmd.PersistentFlags().String(option.Name, viper.GetString(option.Name), option.Description)
		case bool:
			serverCmd.PersistentFlags().Bool(option.Name, viper.GetBool(option.Name), option.Description)
		case time.Duration:
			serverCmd.PersistentFlags().Duration(option.Name, viper.GetDuration(option.Name), option.Description)
		case []string:
			serverCmd.PersistentFlags().StringSlice(option.Name, viper.GetStringSlice(option.Name), option.Description)
		default:
			panic("Invalid type for option default for option '" + option.Name + "'.")
		}
	}

	rootCmd.AddCommand(serverCmd)
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts the gatekeeper server.",
	PreRun: func(c *cobra.Command, a []string) {
		bindViperFlags(c, serverOptions)
	},
	Run: gatekeeperServer,
}

func intro() {
	fmt.Println(" __")
	fmt.Println("/__ _ _|_ _ |/  _  _ |_) _  __")
	fmt.Println("\\_|(_| |_(/_|\\ (/_(/_|  (/_ |")
	fmt.Println("github.com/nemosupremo/vault-gatekeeper")
	fmt.Println("Version: " + Version)
}

func gatekeeperConf() gatekeeper.Config {
	var uns unsealer.Unsealer
	if viper.GetString("vault-token") != "" {
		uns = unsealer.TokenUnsealer{viper.GetString("vault-token")}
	} else if viper.GetString("auth-token-wrapped") != "" {
		uns = unsealer.WrappedTokenUnsealer{viper.GetString("auth-token-wrapped")}
	} else if viper.GetString("auth-app-role") != "" {
		uns = unsealer.AppRoleUnsealer{
			RoleId:   viper.GetString("auth-app-role"),
			SecretId: viper.GetString("auth-app-secret"),
		}
	} else if viper.GetBool("auth-aws-ec2") || viper.GetString("auth-aws-iam") != "" {
		uns = unsealer.AwsUnsealer{
			Role:  viper.GetString("auth-aws-iam"),
			Nonce: viper.GetString("auth-aws-nonce"),
		}
	}

	conf := gatekeeper.Config{
		ListenAddress:  viper.GetString("listen-addr"),
		TlsCert:        viper.GetString("tls-cert"),
		TlsKey:         viper.GetString("tls-key"),
		Schedulers:     strings.Split(viper.GetString("schedulers"), ","),
		Store:          viper.GetString("usage-store"),
		StoreVaultPath: viper.GetString("usage-store-vault-path"),
		Peers:          viper.GetString("peers"),
		HostCheck:      viper.GetBool("host-check"),
		UseImageNames:  viper.GetBool("use-image-name"),

		PolicyPath:  path.Join("v1", viper.GetString("policy-path")),
		MaxTaskLife: viper.GetDuration("task-grace"),

		Unsealer: uns,

		Version: Version,
	}

	if len(conf.Schedulers) > 0 {
		conf.DefaultScheduler = conf.Schedulers[0]
	}

	conf.Vault.Address = viper.GetString("vault-addr")
	conf.Vault.CaCert = viper.GetString("vault-cacert")
	conf.Vault.CaPath = viper.GetString("vault-capath")
	conf.Vault.ClientCert = viper.GetString("vault-client-cert")
	conf.Vault.ClientKey = viper.GetString("vault-client-key")
	conf.Vault.Insecure = viper.GetBool("vault-skip-verify")
	conf.Vault.KvVersion = viper.GetString("vault-kv-version")
	conf.Vault.AppRoleMount = viper.GetString("vault-approle-mount")

	if !strings.HasSuffix(conf.Vault.Address, "/") {
		conf.Vault.Address = conf.Vault.Address + "/"
	}

	conf.Metrics.Ticker = viper.GetDuration("metrics-ticker")
	conf.Metrics.Statsd.Host = viper.GetString("metrics-statsd")
	conf.Metrics.Statsd.Prefix = viper.GetString("metrics-statsd-prefix")
	conf.Metrics.Statsd.Influx = viper.GetBool("metrics-statsd-influx")
	conf.Metrics.Statsd.Datadog = viper.GetBool("metrics-statsd-datadog")


	conf.LocalDevMode = viper.GetBool("local-dev-mode")
	conf.Vault.PublicAddr = viper.GetString("vault-public-addr")
	return conf
}

func gatekeeperServer(*cobra.Command, []string) {
	intro()

	conf := gatekeeperConf()

	if conf.LocalDevMode == true {
		localDevMode()
	}

	if g, err := gatekeeper.NewGatekeeper(conf); err == nil {
		logrus.Infof("Starting Gatekeeper on %v", conf.ListenAddress)
		if err := g.Serve(); err != nil {
			logrus.Fatalf("Failed to start gatekeeper server: %v", err)
		}
	} else {
		logrus.Fatalf("Failed to start gatekeeper: %v", err)
	}
}

func localDevMode() {
	message := "You have enabled local development mode that would by pass any scheduler check. This is not recommended for production use."
	fmt.Printf("%s\n", message)
}