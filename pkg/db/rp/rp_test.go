/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rp

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

func TestNew(t *testing.T) {
	t.Run("returns instance", func(t *testing.T) {
		c, err := New(memstore.NewProvider())
		require.NoError(t, err)
		require.NotNil(t, c)
	})

	t.Run("wraps store creation error", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&mockstorage.Provider{ErrCreateStore: expected})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error opening store", func(t *testing.T) {
		expected := errors.New("test")
		_, err := New(&mockstorage.Provider{ErrOpenStoreHandle: expected})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestStore_SaveRP(t *testing.T) {
	t.Run("saves RP", func(t *testing.T) {
		expected := &Tenant{
			ClientID:  uuid.New().String(),
			PublicDID: uuid.New().String(),
			Label:     uuid.New().String(),
		}
		store := &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: make(map[string][]byte),
			},
		}
		s, err := New(store)
		require.NoError(t, err)
		err = s.SaveRP(expected)
		require.NoError(t, err)
		bits := store.Store.Store[clientIDKey(expected.ClientID)]
		require.NotZero(t, bits)
		result := &Tenant{}
		err = json.Unmarshal(bits, result)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
}

func TestStore_GetRP(t *testing.T) {
	t.Run("fetches tenant", func(t *testing.T) {
		expected := &Tenant{
			ClientID:  uuid.New().String(),
			PublicDID: uuid.New().String(),
			Label:     uuid.New().String(),
		}
		s, err := New(memstore.NewProvider())
		require.NoError(t, err)
		err = s.SaveRP(expected)
		require.NoError(t, err)
		result, err := s.GetRP(expected.ClientID)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("error not found", func(t *testing.T) {
		s, err := New(memstore.NewProvider())
		require.NoError(t, err)
		_, err = s.GetRP("")
		require.Error(t, err)
	})
}

func TestStore_SaveUserConnection(t *testing.T) {
	t.Run("saves connection", func(t *testing.T) {
		expected := newConn()
		store := &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: make(map[string][]byte),
			},
		}
		s, err := New(store)
		require.NoError(t, err)
		err = s.SaveUserConnection(expected)
		require.NoError(t, err)
		bits := store.Store.Store[userConnectionKey(expected.RP.ClientID, expected.User.Subject)]
		require.NotZero(t, bits)
		result := &UserConnection{}
		err = json.Unmarshal(bits, result)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
}

func TestStore_GetUserConnection(t *testing.T) {
	t.Run("fetches connection", func(t *testing.T) {
		expected := newConn()
		s, err := New(memstore.NewProvider())
		require.NoError(t, err)
		err = s.SaveUserConnection(expected)
		require.NoError(t, err)
		result, err := s.GetUserConnection(expected.RP.ClientID, expected.User.Subject)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("error not found", func(t *testing.T) {
		s, err := New(memstore.NewProvider())
		require.NoError(t, err)
		_, err = s.GetUserConnection("", "")
		require.Error(t, err)
	})
}

func newConn() *UserConnection {
	return &UserConnection{
		User: &User{
			Subject: uuid.New().String(),
			DID:     uuid.New().String(),
		},
		RP: &Tenant{
			ClientID:  uuid.New().String(),
			PublicDID: uuid.New().String(),
			Label:     uuid.New().String(),
		},
		Request: &DataRequest{
			Scope: []string{uuid.New().String()},
		},
	}
}
