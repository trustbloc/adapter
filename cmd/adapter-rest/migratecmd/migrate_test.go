/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package migratecmd

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/google/uuid"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/require"
	"github.com/xo/dburl"

	_ "github.com/go-sql-driver/mysql"
)

//nolint:gochecknoglobals
var containerName = "edgeadapter_migrate_tests_" + strings.ReplaceAll(uuid.New().String(), "-", "")

//nolint:gochecknoglobals
var containerPort int

func startMySQL() error {
	var err error

	containerPort, err = freeport.GetFreePort()
	if err != nil {
		return fmt.Errorf("failed to obtain a port from the os : %w", err)
	}

	//nolint:gosec
	err = exec.Command("docker", "run",
		"--name", containerName,
		"-e", "MYSQL_ROOT_PASSWORD=secret",
		"-e", "MYSQL_DATABASE=edgeadapter",
		"-d",
		"-p", fmt.Sprintf("%d:3306", containerPort),
		"mysql:8.0.20").Run()
	if err != nil {
		return fmt.Errorf("failed to start mysql : %w", err)
	}

	db, err := sql.Open("mysql", fmt.Sprintf("root:secret@tcp(localhost:%d)/edgeadapter", containerPort))
	if err != nil {
		return fmt.Errorf("failed to start mysql : %w", err)
	}

	err = backoff.Retry(
		db.Ping,
		backoff.WithMaxRetries(backoff.NewConstantBackOff(500*time.Millisecond), 40),
	)
	if err != nil {
		return fmt.Errorf("failed to ping mysql : %w", err)
	}

	return nil
}

func stopMySQL() error {
	//nolint:gosec
	err := exec.Command("docker", "stop", containerName).Run()
	if err != nil {
		return fmt.Errorf("failed to stop mysql : %w", err)
	}

	return nil
}

func TestMain(m *testing.M) {
	err := startMySQL()
	if err != nil {
		panic(err)
	}

	code := m.Run()

	err = stopMySQL()
	if err != nil {
		panic(fmt.Errorf("failed to stop mysql : %w", err))
	}

	os.Exit(code)
}

func TestMigrateCmdInvalidArgs(t *testing.T) {
	t.Run("missing dsn", func(t *testing.T) {
		cmd := GetMigrateCmd()
		cmd.SetArgs([]string{"--" + migrationDirectionFlagName, "up"})

		err := cmd.Execute()
		require.Error(t, err)
	})

	t.Run("invalid dsn", func(t *testing.T) {
		cmd := GetMigrateCmd()
		cmd.SetArgs([]string{"--" + datasourceNameFlagName, "INVALID"})

		err := cmd.Execute()
		require.Error(t, err)
	})

	t.Run("missing migration direction", func(t *testing.T) {
		cmd := GetMigrateCmd()
		cmd.SetArgs([]string{
			"--" + datasourceNameFlagName, fmt.Sprintf("mysql://root:secret@localhost:%d/edgeadapter", containerPort),
		})

		err := cmd.Execute()
		require.Error(t, err)
	})

	t.Run("invalid migration direction value", func(t *testing.T) {
		cmd := GetMigrateCmd()
		cmd.SetArgs([]string{
			"--" + datasourceNameFlagName, fmt.Sprintf("mysql://root:secret@localhost:%d/edgeadapter", containerPort),
			"--" + migrationDirectionFlagName, "invalid",
		})

		err := cmd.Execute()
		require.Error(t, err)
	})
}

func TestMigration(t *testing.T) {
	t.Run("migrate up", func(t *testing.T) {
		cmd := GetMigrateCmd()
		cmd.SetArgs([]string{
			"--" + datasourceNameFlagName, fmt.Sprintf("mysql://root:secret@localhost:%d/edgeadapter?parseTime=true", containerPort), //nolint:lll
			"--" + migrationDirectionFlagName, "up",
		})

		err := cmd.Execute()
		require.NoError(t, err)
		verifySchemas(t,
			fmt.Sprintf("mysql://root:secret@localhost:%d/edgeadapter", containerPort),
			[]string{"end_user", "oidc_request"},
			false)
	})

	t.Run("migrate down", func(t *testing.T) {
		cmd := GetMigrateCmd()
		cmd.SetArgs([]string{
			"--" + datasourceNameFlagName, fmt.Sprintf("mysql://root:secret@localhost:%d/edgeadapter?parseTime=true", containerPort), //nolint:lll
			"--" + migrationDirectionFlagName, "up",
		})

		err := cmd.Execute()
		require.NoError(t, err)

		cmd.SetArgs([]string{
			"--" + datasourceNameFlagName, fmt.Sprintf("mysql://root:secret@localhost:%d/edgeadapter?parseTime=true", containerPort), //nolint:lll
			"--" + migrationDirectionFlagName, "down",
		})

		err = cmd.Execute()
		require.NoError(t, err)

		verifySchemas(t,
			fmt.Sprintf("mysql://root:secret@localhost:%d/edgeadapter", containerPort),
			[]string{"end_user", "oidc_request"},
			true)
	})
}

func verifySchemas(t *testing.T, dsn string, tables []string, mustFail bool) {
	db, err := dburl.Open(dsn)
	require.NoError(t, err)

	for _, table := range tables {
		_, err = db.Exec("select * from " + table)

		if !mustFail {
			require.NoError(t, err)
		}
	}
}
