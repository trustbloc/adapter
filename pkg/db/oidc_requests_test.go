/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOIDCRequests_Insert(t *testing.T) {
	t.Run("inserts request", func(t *testing.T) {
		db := newDB(t)
		user := &EndUser{Sub: "test"}
		err := NewEndUsers(db).Insert(user)
		require.NoError(t, err)
		expected := &OIDCRequest{
			EndUserID: user.ID,
			Scopes:    []string{"foo", "bar"},
		}
		o := NewOIDCRequests(db)

		err = o.Insert(expected)
		require.NoError(t, err)
		require.NotZero(t, expected.ID)
		verifyOidcRequest(t, expected, db)
	})

	t.Run("cannot insert request without relation to user", func(t *testing.T) {
		expected := &OIDCRequest{
			Scopes: []string{"foo", "bar"},
		}
		db := newDB(t)
		o := NewOIDCRequests(db)

		err := o.Insert(expected)
		require.Error(t, err)
	})
}

func verifyOidcRequest(t *testing.T, expected *OIDCRequest, db *sql.DB) {
	var (
		id        int64
		endUserID int64
		scopes    string
	)

	row := db.QueryRow("select * from oidc_request where id = ?", expected.ID)
	require.NotNil(t, row)
	err := row.Scan(&id, &endUserID, &scopes)
	require.NoError(t, err)
	require.Equal(t, expected.ID, id)
	require.Equal(t, expected.EndUserID, endUserID)
	require.Equal(t, expected.Scopes, strings.Split(scopes, ","))
}
