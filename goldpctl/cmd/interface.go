// Copyright © 2016 NAME HERE <EMAIL ADDRESS>
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

	"github.com/docopt/docopt-go"
	"github.com/ishidawataru/goldp/config"
	"github.com/spf13/cobra"
)

// interfaceCmd represents the interface command
var interfaceCmd = &cobra.Command{
	Use:   "interface",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Work your own magic here
		fmt.Println("interface called")
	},
}

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			list, err := client.ListInterface()
			if err != nil {
				return err
			}
			fmt.Printf("%#v", list)
			return nil
		},
	}
}

func newAddCmd() *cobra.Command {
	usage := `usage: add <name> [<address>...]`
	return &cobra.Command{
		Use: "add",
		RunE: func(cmd *cobra.Command, args []string) error {
			i := &config.Interface{}
			m, err := docopt.Parse(usage, args, false, "", false)
			if err != nil {
				return err
			}
			i.Name = m["<name>"].(string)
			i.Addresses = m["<address>"].([]string)
			return client.AddInterface(i)
		},
	}
}

func newDeleteCmd() *cobra.Command {
	usage := `usage: delete <name>`
	return &cobra.Command{
		Use: "delete",
		RunE: func(cmd *cobra.Command, args []string) error {
			i := &config.Interface{}
			m, err := docopt.Parse(usage, args, false, "", false)
			if err != nil {
				return err
			}
			i.Name = m["<name>"].(string)
			return client.DeleteInterface(i)
		},
	}
}

func init() {
	RootCmd.AddCommand(interfaceCmd)
	interfaceCmd.AddCommand(newListCmd(), newAddCmd(), newDeleteCmd())

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// interfaceCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// interfaceCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
