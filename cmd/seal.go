package cmd

import (
	"net/url"

	"github.com/franela/goreq"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	viper.SetDefault("gatekeeper-addr", defaultGatekeeperAddr)

	sealCmd.PersistentFlags().String("gatekeeper-addr", viper.GetString("gatekeeper-addr"), "Hostname address of the gatekeeper instance.")

	rootCmd.AddCommand(sealCmd)
}

var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Seals the Gatekeeper instance",
	PreRun: func(c *cobra.Command, a []string) {
		viper.BindPFlag("gatekeeper-addr", c.PersistentFlags().Lookup("gatekeeper-addr"))
	},
	Run: gatekeeperSeal,
}

func gatekeeperSeal(*cobra.Command, []string) {
	log.Infof("Sealing gatekeeper at %v", viper.GetString("gatekeeper-addr"))
	if url, err := url.Parse(viper.GetString("gatekeeper-addr")); err == nil {
		url.Path = "/seal"
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
					log.Info("Sealed.")
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
