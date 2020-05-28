/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

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

	_ "github.com/go-sql-driver/mysql"
)

//nolint:gochecknoglobals
var containerName = "edgeadapter_mysql_tests_" + strings.ReplaceAll(uuid.New().String(), "-", "")

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

	err = createSchemas(schemas())
	if err != nil {
		mysqlErr := stopMySQL()
		if mysqlErr != nil {
			fmt.Printf("WARNING - failed to stop mysql : %s", mysqlErr)
		}

		panic(fmt.Errorf("failed to create schemas : %w", err))
	}

	code := m.Run()

	err = stopMySQL()
	if err != nil {
		panic(fmt.Errorf("failed to stop mysql : %w", err))
	}

	os.Exit(code)
}

func newDB(t *testing.T) *sql.DB {
	db, err := sql.Open("mysql", fmt.Sprintf("root:secret@tcp(localhost:%d)/edgeadapter", containerPort))
	require.NoError(t, err)

	t.Cleanup(func() {
		err = db.Close()
		if err != nil {
			panic(fmt.Errorf("failed to close DB : %w", err))
		}
	})

	return db
}

func createSchemas(schemas []string) (e error) {
	db, err := sql.Open("mysql", fmt.Sprintf("root:secret@tcp(localhost:%d)/edgeadapter", containerPort))
	if err != nil {
		return fmt.Errorf("failed to open db : %w", err)
	}

	defer func() {
		err = db.Close()
		if err != nil {
			e = fmt.Errorf("failed to close DB : %w", err)
		}
	}()

	err = backoff.Retry(
		db.Ping,
		backoff.WithMaxRetries(backoff.NewConstantBackOff(500*time.Millisecond), 40), // 20 seconds max
	)
	if err != nil {
		return fmt.Errorf("failed to ping mysql : %w", err)
	}

	for _, s := range schemas {
		_, err = db.Exec(s)
		if err != nil {
			return fmt.Errorf("failed to execute DDL [%s] : %w", s, err)
		}
	}

	return nil
}
