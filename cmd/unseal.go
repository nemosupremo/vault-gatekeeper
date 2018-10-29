package cmd

import (
	"net/url"

	"vault-gatekeeper/scheduler"

	"github.com/franela/goreq"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var unsealOptions []scheduler.Args

func init() {
	unsealCmd.Flags().SortFlags = false
	unsealCmd.PersistentFlags().SortFlags = false
	options := []scheduler.Args{
		{"gatekeeper-addr", defaultGatekeeperAddr, "The address to gatekeeper."},

		{"vault-token", "", "Unseal gatekeeper at startup with a Vault token."},
		{"auth-token-wrapped", "", "Unseal gatekeeper at startup with a Vault token that is stored with a response wrapped temp token."},

		{"auth-app-role", "", "Unseal gatekeeper at startup with a Vault token retrieved using this app role."},
		{"auth-app-secret", "", "The app role secret_id to be used."},

		{"auth-aws-ec2", false, "Unseal gatekeeper at startup using EC2 login."},
		{"auth-aws-iam", "", "Unseal gatekeeper at startup using IAM login."},
		{"auth-aws-nonce", "", "AWS-EC2 nonce for repeated authentication."},

		{"auth-gh-token", "", "Vault authorized github personal token."},
	}
	unsealOptions = options

	for _, option := range options {
		viper.SetDefault(option.Name, option.Default)
	}

	for _, option := range options {
		switch option.Default.(type) {
		case string:
			unsealCmd.PersistentFlags().String(option.Name, viper.GetString(option.Name), option.Description)
		case bool:
			unsealCmd.PersistentFlags().Bool(option.Name, viper.GetBool(option.Name), option.Description)
		default:
			panic("Invalid type for option default for option '" + option.Name + "'.")
		}
	}

	rootCmd.AddCommand(unsealCmd)
}

var unsealCmd = &cobra.Command{
	Use:   "unseal [method]",
	Short: "Unseals the Gatekeeper instance",
	Long: `Unseals the gatekeeper instance. The available methods are:

* token
* token-wrapped
* approle
* aws
* github
`,
	PreRun: func(c *cobra.Command, a []string) {
		bindViperFlags(c, unsealOptions)
	},
	Run:  gatekeeperUnseal,
	Args: cobra.MinimumNArgs(1),
}

func gatekeeperUnseal(cmd *cobra.Command, args []string) {
	var body struct {
		Method string `json:"method"`

		Token string `json:"token"`

		PersonalToken string `json:"personal_token"`

		RoleId   string `json:"role_id"`
		SecretId string `json:"secret_id"`

		Role  string `json:"aws_role"`
		Nonce string `json:"aws_nonce"`
	}
	body.Method = args[0]
	switch args[0] {
	case "token":
		body.Token = viper.GetString("vault-token")
		if body.Token == "" {
			log.Fatal("'token` method requires `vault-token` to be set.")
		}
	case "token-wrapped":
		body.Token = viper.GetString("auth-token-wrapped")
		if body.Token == "" {
			log.Fatal("'token-wrapped` method requires `auth-token-wrapped` to be set.")
		}
	case "approle":
		body.RoleId = viper.GetString("auth-app-role")
		body.SecretId = viper.GetString("auth-app-secret")
		if body.RoleId == "" {
			if len(args) >= 3 {
				body.RoleId = args[1]
				body.SecretId = args[2]
			}
		}
		if body.RoleId == "" {
			log.Fatal("'approle` method requires `auth-app-role` to be set.")
		}
	case "aws":
		body.Role = viper.GetString("auth-aws-iam")
		body.Nonce = viper.GetString("auth-aws-nonce")
	case "github":
		body.PersonalToken = viper.GetString("auth-gh-token")
		if body.PersonalToken == "" {
			log.Fatal("'github` method requires `auth-gh-token` to be set.")
		}
	default:
		log.Fatalf("Invalid method '%s'", args[0])
	}

	log.Infof("Unsealing gatekeeper at %v", viper.GetString("gatekeeper-addr"))
	if url, err := url.Parse(viper.GetString("gatekeeper-addr")); err == nil {
		url.Path = "/unseal"
		req, err := goreq.Request{
			Uri:         url.String(),
			Method:      "POST",
			Body:        body,
			ContentType: "application/json",
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
					log.Info("Unsealed.")
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
