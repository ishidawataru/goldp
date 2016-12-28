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
	"strconv"

	"github.com/docopt/docopt-go"
	"github.com/spf13/cobra"
)

// mappingCmd represents the mapping command
var mappingCmd = &cobra.Command{
	Use:   "mapping",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Work your own magic here
		fmt.Println("mapping called")
	},
}

func newMappingAddCmd() *cobra.Command {
	usage := `usage: add <label> <prefix>...`
	return &cobra.Command{
		Use: "add",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := docopt.Parse(usage, args, false, "", false)
			if err != nil {
				return err
			}
			label, err := strconv.Atoi(m["<label>"].(string))
			if err != nil {
				return err
			}
			fec := m["<prefix>"].([]string)
			return client.AddLocalLabelMapping(label, fec...)
		},
	}

}

func newMappingDeleteCmd() *cobra.Command {
	usage := `usage: delete <prefix>...`
	return &cobra.Command{
		Use: "delete",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := docopt.Parse(usage, args, false, "", false)
			if err != nil {
				return err
			}
			fec := m["<prefix>"].([]string)
			return client.DeleteLocalLabelMapping(fec...)
		},
	}

}

func newMappingGetCmd() *cobra.Command {
	usage := `usage: get <prefix>`
	return &cobra.Command{
		Use: "get",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := docopt.Parse(usage, args, false, "", false)
			if err != nil {
				return err
			}
			prefix := m["<prefix>"].(string)
			mapping, err := client.GetLabelMapping(prefix)
			if err != nil {
				return err
			}
			fmt.Printf("label: %v\n", mapping)
			return nil
		},
	}

}

func newMappingListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			list, err := client.ListLabelMapping()
			if err != nil {
				return err
			}
			for _, m := range list {
				fmt.Println(m)
			}
			return nil
		},
	}

}

func init() {
	RootCmd.AddCommand(mappingCmd)

	mappingCmd.AddCommand(newMappingAddCmd(), newMappingDeleteCmd(), newMappingGetCmd(), newMappingListCmd())

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// mappingCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// mappingCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
