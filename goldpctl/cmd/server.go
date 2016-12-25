// Copyright © 2016 Wataru Ishida <ishida.wataru@lab.ntt.co.jp>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"strconv"

	"github.com/docopt/docopt-go"
	"github.com/ishidawataru/goldp/config"
	"github.com/spf13/cobra"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		server, err := client.GetServer()
		if err != nil {
			return err
		}
		fmt.Printf("%#v", server)
		return nil
	},
}

func newStartCmd() *cobra.Command {
	usage := `usage:
	    start router-id <router-id> [ hold-time <hold-time> ] [ local-address <local-address> ] [ hello-interval <hello-interval> ]
`

	return &cobra.Command{
		Use: "start",
		RunE: func(cmd *cobra.Command, args []string) error {
			g := &config.Global{}
			if err := config.SetGlobalDefault(g); err != nil {
				return err
			}
			m, err := docopt.Parse(usage, args, false, "", false)
			if err != nil {
				return err
			}
			if m["router-id"].(bool) {
				g.RouterId = m["<router-id>"].(string)
			}
			if m["hold-time"].(bool) {
				h, err := strconv.Atoi(m["<hold-time>"].(string))
				if err != nil {
					return err
				}
				g.HoldTime = h
			}
			return client.StartServer(g)
		},
	}
}

func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use: "stop",
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.StopServer()
		},
	}
}

func init() {
	RootCmd.AddCommand(serverCmd)
	serverCmd.AddCommand(newStartCmd(), newStopCmd())

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serverCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serverCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
