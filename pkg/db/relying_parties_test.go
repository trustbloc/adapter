/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"database/sql"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRelyingParties_Insert(t *testing.T) {
	t.Run("inserts relying party", func(t *testing.T) {
		expected := &RelyingParty{
			ClientID: uuid.New().String(),
			DID:      newDID(t),
		}
		db := newDB(t)
		err := NewRelyingParties(db).Insert(expected)
		require.NoError(t, err)
		require.NotZero(t, expected.ID)
		verifyRelyingParty(t, expected, db)
	})

	t.Run("fails if db is closed", func(t *testing.T) {
		db := newDB(t)
		err := db.Close()
		require.NoError(t, err)
		err = NewRelyingParties(db).Insert(&RelyingParty{
			ClientID: uuid.New().String(),
			DID:      newDID(t),
		})
		require.Error(t, err)
	})
}

func TestRelyingParties_FindByClientID(t *testing.T) {
	t.Run("finds relying party", func(t *testing.T) {
		expected := &RelyingParty{
			ClientID: uuid.New().String(),
			DID:      newDID(t),
		}
		rps := NewRelyingParties(newDB(t))
		err := rps.Insert(expected)
		require.NoError(t, err)
		result, err := rps.FindByClientID(expected.ClientID)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("fails if db is closed", func(t *testing.T) {
		db := newDB(t)
		err := db.Close()
		require.NoError(t, err)
		_, err = NewRelyingParties(db).FindByClientID("123")
		require.Error(t, err)
	})

	t.Run("fails on malformed DID", func(t *testing.T) {
		clientID := uuid.New().String()
		malformed := "malformed"
		_, err := did.Parse(malformed)
		require.Error(t, err)
		db := newDB(t)
		_, err = db.Exec(`insert into relying_party (client_id, did) values (?, ?)`, clientID, malformed)
		require.NoError(t, err)
		_, err = NewRelyingParties(db).FindByClientID(clientID)
		require.Error(t, err)
	})
}

func verifyRelyingParty(t *testing.T, expected *RelyingParty, db *sql.DB) {
	var dbDID string

	result := &RelyingParty{}
	err := db.QueryRow("select * from relying_party where id = ?", expected.ID).
		Scan(&result.ID, &result.ClientID, &dbDID)
	require.NoError(t, err)

	result.DID, err = did.Parse(dbDID)
	require.NoError(t, err)
	require.Equal(t, expected, result)
}

func newDID(t *testing.T) *did.DID {
	d, err := did.Parse("did:example:" + uuid.New().String())
	require.NoError(t, err)

	return d
}
