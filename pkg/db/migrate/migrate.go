/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package migrate

import (
	"database/sql"
	"fmt"

	"github.com/gobuffalo/packr/v2"
	migrate "github.com/rubenv/sql-migrate"
)

// Up upgrades the schemas at the db.
func Up(dialect string, db *sql.DB) (int, error) {
	return doMigration(dialect, db, migrate.Up)
}

// Down downgrades the schemas at the db.
func Down(dialect string, db *sql.DB) (int, error) {
	return doMigration(dialect, db, migrate.Down)
}

func doMigration(dialect string, db *sql.DB, dir migrate.MigrationDirection) (int, error) {
	migrations := &migrate.PackrMigrationSource{
		Box: packr.New("migrations", "./files"),
	}

	n, err := migrate.Exec(db, dialect, migrations, dir)
	if err != nil {
		err = fmt.Errorf("failed to apply migrations : %w", err)
	}

	return n, err
}
