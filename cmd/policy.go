package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"

	"github.com/packetloop/vault-gatekeeper"
	"github.com/nemosupremo/vault-gatekeeper/policy"
	"github.com/nemosupremo/vault-gatekeeper/scheduler"
	"github.com/nemosupremo/vault-gatekeeper/vault"

	"github.com/franela/goreq"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var policyOptions []scheduler.Args

func init() {
	policyCmd.Flags().SortFlags = false
	policyCmd.PersistentFlags().SortFlags = false
	options := []scheduler.Args{
		{"gatekeeper-addr", defaultGatekeeperAddr, "The address to gatekeeper."},

		{"vault-addr", defaultVaultAddr, "The address to the vault server."},
		{"vault-client-cert", "", "Path to a PEM-encoded client certificate on the local disk. This file is used for TLS communication with the Vault server. (This is different from the TLS Certificates Auth Method)."},
		{"vault-client-key", "", "Path to an unencrypted, PEM-encoded private key on disk which corresponds to the matching client certificate. (This is different from the TLS Certificates Auth Method)."},
		{"vault-skip-verify", false, "Skip TLS verification of Vault's SSL certificate."},
		{"vault-kv-version", defaultVaultKvVer, "Vault KV backend version that is used for the policy-path. Either v1 or v2."},

		{"policy-path", defaultPolicyPath, "The path on Vault to a v2 kv backend where gatekeeper can load the token policy. Gatekeeper will merge all policies at this path and its children's paths."},

		{"vault-token", "", "Unseal gatekeeper at startup with a Vault token."},
		{"auth-token-wrapped", "", "Unseal gatekeeper at startup with a Vault token that is stored with a response wrapped temp token."},

		{"auth-app-role", "", "Unseal gatekeeper at startup with a Vault token retrieved using this app role."},
		{"auth-app-secret", "", "The app role secret_id to be used."},

		{"auth-aws-ec2", false, "Unseal gatekeeper at startup using EC2 login."},
		{"auth-aws-iam", "", "Unseal gatekeeper at startup using IAM login."},
		{"auth-aws-nonce", "", "AWS-EC2 nonce for repeated authentication."},

		{"auth-gh-token", "", "Vault authorized github personal token."},
	}
	policyOptions = options

	for _, option := range options {
		viper.SetDefault(option.Name, option.Default)
	}

	for _, option := range options {
		switch option.Default.(type) {
		case string:
			policyCmd.PersistentFlags().String(option.Name, viper.GetString(option.Name), option.Description)
		case bool:
			policyCmd.PersistentFlags().Bool(option.Name, viper.GetBool(option.Name), option.Description)
		default:
			panic("Invalid type for option default for option '" + option.Name + "'.")
		}
	}

	policyCmd.AddCommand(policyUpdateCmd)
	policyCmd.AddCommand(policyReloadCmd)
	rootCmd.AddCommand(policyCmd)
}

var policyCmd = &cobra.Command{
	Use:   "policy [command]",
	Short: "View the current gatekeeper policy file.",
	PreRun: func(c *cobra.Command, a []string) {
		bindViperFlags(c, policyOptions)
	},
	Run: viewPolicies,
}

var policyUpdateCmd = &cobra.Command{
	Use:   "update [file]",
	Short: "Update the current gatekeeper policy file from a file. Specify '-' to read from stdin.",
	PreRun: func(c *cobra.Command, a []string) {
		bindViperFlags(c.Parent(), policyOptions)
	},
	Run:  updatePolicies,
	Args: cobra.MinimumNArgs(1),
}

var policyReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload the gatekeeper policy on an instance.",
	PreRun: func(c *cobra.Command, a []string) {
		bindViperFlags(c.Parent(), policyOptions)
	},
	Run: reloadPolicies,
}

func viewPolicies(*cobra.Command, []string) {
	conf := gatekeeperConf()
	conf.Store = "_null_cmd"
	conf.Schedulers = []string{"_null_cmd"}
	conf.Peers = ""

	log.Infof("Viewing policies at '%s'", conf.PolicyPath)
	if g, err := gatekeeper.NewGatekeeper(conf); err == nil {
		if policies, err := g.GetPolicyConfig(); err == nil {
			fmt.Println(string(policies))
		} else {
			log.Fatalf("Failed to load policies: %v", err)
		}
	} else {
		log.Fatalf("Failed to initialize gatekeeper for policy reading: %v", err)
	}
}

func updatePolicies(c *cobra.Command, args []string) {
	var policyReader io.ReadCloser
	if args[0] == "-" {
		policyReader = os.Stdin
		log.Info("Reading policy from stdin...")
	} else {
		if f, err := os.Open(args[0]); err == nil {
			log.Infof("Reading policy from '%s'...", args[0])
			policyReader = f
		} else {
			log.Fatalf("Could not open file '%s': %v", args[0], err)
		}
	}

	if policyJson, err := ioutil.ReadAll(policyReader); err == nil {
		policyReader.Close()
		if _, err := policy.LoadPoliciesFromJson(policyJson); err != nil {
			log.Fatalf("Validation of policy file failed: %v", err)
		}

		conf := gatekeeperConf()
		conf.Store = "_null_cmd"
		conf.Schedulers = []string{"_null_cmd"}
		conf.Peers = ""
		conf.SkipPolicyLoading = true

		if g, err := gatekeeper.NewGatekeeper(conf); err == nil {
			r, err := vault.Request{
				goreq.Request{
					Uri:             vault.Path(conf.PolicyPath),
					MaxRedirects:    10,
					RedirectHeaders: true,
					Body: struct {
						Data json.RawMessage `json:"data"`
					}{json.RawMessage(policyJson)},
					ContentType: "application/json",
					Method:      "POST",
				}.WithHeader("X-Vault-Token", g.Token),
			}.Do()
			if err == nil {
				defer r.Body.Close()
				switch r.StatusCode {
				case 200, 204:
					log.Info("Wrote policy successfully.")
				default:
					var e vault.Error
					e.Code = r.StatusCode
					if err := r.Body.FromJsonTo(&e); err == nil {
						log.Fatalf("Failed to write policy: %v", err)
					} else {
						log.Fatalf("Failed to communicate with vault: %v", err)
					}
				}
			} else {
				log.Fatalf("Failed to communicate with vault: %v", err)
			}
		} else {
			log.Fatalf("Failed to initialize gatekeeper for policy writing: %v", err)
		}
	} else {
		log.Fatalf("Could not read file '%s': %v", args[0], err)
	}

}

func reloadPolicies(cmd *cobra.Command, args []string) {
	log.Infof("Reloading policies on gatekeeper instance at %v", viper.GetString("gatekeeper-addr"))
	if url, err := url.Parse(viper.GetString("gatekeeper-addr")); err == nil {
		url.Path = "/policies/reload"
		req, err := goreq.Request{
			Uri:    url.String(),
			Method: "POST",
		}.Do()
		if err == nil {
			defer req.Body.Close()
			var resp struct {
				Unsealed bool   `json:"unsealed"`
				Message  string `json:"message"`
				Error    string `json:"error"`
			}
			if err := req.Body.FromJsonTo(&resp); err == nil {
				switch req.StatusCode {
				case 200, 204:
					log.Info("Policies reloaded.")
				default:
					log.Warnf("Error from gatekeeper: %v", resp.Error)
				}
			} else {
				log.Fatalf("Error parsing response: %v", err)
			}
		} else {
			log.Fatalf("Error communicating with gatekeeper: %v", err)
		}
	} else {
		log.Fatalf("Invalid value for gatekeeper-addr '%s': %v", viper.GetString("gatekeeper-addr"), err)
	}
}
