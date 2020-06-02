/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package migratecmd

import (
	"fmt"

	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/xo/dburl"

	"github.com/trustbloc/edge-adapter/pkg/db/migrate"
)

const (
	datasourceNameFlagName  = "dsn"
	datasourceNameFlagUsage = "Datasource Name with credentials if required," +
		" eg. mysql://root:secret@localhost:3306/adapter?parseTime=true"

	migrationDirectionFlagName  = "dir"
	migrationDirectionFlagUsage = "Direction in which to migrate the datasource schemas. Valid values: 'up', 'down'."
)

var logger = log.New("edge-adapter/migrate")

type config struct {
	dsn *dburl.URL
	dir int
}

// GetMigrateCmd returns the cobra migrate command.
func GetMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "DB migration.",
		Long:  "Upgrades and downgrades SQL database schemas.",
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getConfig(cmd)
			if err != nil {
				return fmt.Errorf("failed to build configuration : %w", err)
			}

			db, err := dburl.Open(conf.dsn.String())
			if err != nil {
				return fmt.Errorf("failed to establish connection to database at %s : %w", conf.dsn, err)
			}

			var n int

			switch conf.dir {
			case 1:
				n, err = migrate.Up(conf.dsn.Driver, db)
			default:
				n, err = migrate.Down(conf.dsn.Driver, db)
			}

			if err != nil {
				return err
			}

			logger.Infof("Successfully applied %d migrations!", n)

			return nil
		},
	}

	createFlags(cmd)

	return cmd
}

func createFlags(cmd *cobra.Command) {
	cmd.Flags().StringP(datasourceNameFlagName, "", "", datasourceNameFlagUsage)
	cmd.Flags().StringP(migrationDirectionFlagName, "", "", migrationDirectionFlagUsage)
}

func getConfig(cmd *cobra.Command) (*config, error) {
	url, err := cmdutils.GetUserSetVarFromString(cmd, datasourceNameFlagName, "", true)
	if err != nil {
		return nil, err
	}

	dsn, err := dburl.Parse(url)
	if err != nil {
		return nil, err
	}

	dir, err := cmdutils.GetUserSetVarFromString(cmd, migrationDirectionFlagName, "", true)
	if err != nil {
		return nil, err
	}

	if dir != "up" && dir != "down" {
		return nil, fmt.Errorf("invalid value for %s: %s", migrationDirectionFlagName, dir)
	}

	var dirN int

	switch dir {
	case "up":
		dirN = 1
	default:
		dirN = -1
	}

	return &config{
		dsn: dsn,
		dir: dirN,
	}, nil
}
