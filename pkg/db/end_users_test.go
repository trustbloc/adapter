/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestEndUsers_Insert(t *testing.T) {
	t.Run("inserts user", func(t *testing.T) {
		expected := &EndUser{
			Sub: uuid.New().String(),
		}
		db := newDB(t)
		u := NewEndUsers(db)

		err := u.Insert(expected)
		require.NoError(t, err)
		require.NotZero(t, expected.ID)
		verifyEndUser(t, expected, db)
	})

	t.Run("fails if db is closed", func(t *testing.T) {
		db := newDB(t)
		err := db.Close()
		require.NoError(t, err)
		err = NewEndUsers(db).Insert(&EndUser{Sub: "123"})
		require.Error(t, err)
	})
}

func verifyEndUser(t *testing.T, expected *EndUser, db *sql.DB) {
	result := &EndUser{}
	row := db.QueryRow("select * from end_user where id = ?", expected.ID)
	require.NotNil(t, row)
	err := row.Scan(&result.ID, &result.Sub)
	require.NoError(t, err)
	require.Equal(t, expected.ID, result.ID)
	require.Equal(t, expected.Sub, result.Sub)
}
