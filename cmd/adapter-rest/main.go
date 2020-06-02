/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/trustbloc/edge-adapter/cmd/adapter-rest/migratecmd"
	"github.com/trustbloc/edge-adapter/cmd/adapter-rest/startcmd"
)

func main() {
	rootCmd := &cobra.Command{
		Use: "adapter-rest",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(startcmd.GetStartCmd(&startcmd.HTTPServer{}))
	rootCmd.AddCommand(migratecmd.GetMigrateCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("failed to run adapter-rest: %s", err.Error())
	}
}
