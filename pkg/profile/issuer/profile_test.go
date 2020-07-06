/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	mockstorage "github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

func TestNew(t *testing.T) {
	t.Run("test new - success", func(t *testing.T) {
		record, err := New(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, record)
	})

	t.Run("test new - success (store exists already)", func(t *testing.T) {
		record, err := New(&mockstorage.Provider{ErrCreateStore: storage.ErrDuplicateStore})
		require.NoError(t, err)
		require.NotNil(t, record)
	})

	t.Run("test new - success", func(t *testing.T) {
		record, err := New(&mockstorage.Provider{ErrCreateStore: errors.New("db provider error")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "db provider error")
		require.Nil(t, record)
	})

	t.Run("test new - success", func(t *testing.T) {
		record, err := New(&mockstorage.Provider{ErrOpenStoreHandle: errors.New("error opening the handler")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error opening the handler")
		require.Nil(t, record)
	})
}

func TestCredentialRecord_SaveProfile(t *testing.T) {
	t.Run("test save profile - success", func(t *testing.T) {
		record, err := New(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, record)

		value := &ProfileData{
			ID:                  "profile1",
			Name:                "Issuer Profile 1",
			SupportedVCContexts: []string{"https://w3id.org/citizenship/v3"},
			CallbackURL:         "http://issuer.example.com/cb",
		}

		err = record.SaveProfile(value)
		require.NoError(t, err)

		k := getDBKey(value.ID)
		v, err := record.store.Get(k)
		require.NoError(t, err)
		require.NotEmpty(t, v)
	})

	t.Run("test save profile - validation failure", func(t *testing.T) {
		record, err := New(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, record)

		value := &ProfileData{}

		err = record.SaveProfile(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile id mandatory")

		value.ID = "profile1"
		err = record.SaveProfile(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile name mandatory")

		value.Name = "Issuer Profile 1"
		err = record.SaveProfile(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "supported vc contexts mandatory")

		value.SupportedVCContexts = []string{"https://w3id.org/citizenship/v3"}
		err = record.SaveProfile(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "callback url is invalid")
	})

	t.Run("test save profile - profile already exists", func(t *testing.T) {
		record, err := New(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, record)

		value := &ProfileData{
			ID:                  "profile1",
			Name:                "Issuer Profile 1",
			SupportedVCContexts: []string{"https://w3id.org/citizenship/v3"},
			CallbackURL:         "http://issuer.example.com/cb",
		}

		err = record.SaveProfile(value)
		require.NoError(t, err)

		// try to save again
		err = record.SaveProfile(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "profile profile1 already exists")
	})
}

func TestGetProfile(t *testing.T) {
	t.Run("test get profile - success", func(t *testing.T) {
		s := make(map[string][]byte)
		require.Equal(t, 0, len(s))

		profileStore, err := New(&mockstorage.Provider{Store: &mockstorage.MockStore{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		profileData := &ProfileData{
			ID: "issuer-1",
		}

		profileJSON, err := json.Marshal(profileData)
		require.NoError(t, err)

		s[getDBKey(profileData.Name)] = profileJSON

		resp, err := profileStore.GetProfile(profileData.Name)
		require.NoError(t, err)

		require.Equal(t, profileData, resp)
	})

	t.Run("test get profile - no data", func(t *testing.T) {
		profileStore, err := New(&mockstorage.Provider{Store: &mockstorage.MockStore{Store: make(map[string][]byte)}})
		require.NoError(t, err)
		require.NotNil(t, profileStore)
		require.NotNil(t, profileStore)

		resp, err := profileStore.GetProfile("issuer-1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "store does not have a value associated with this key")
		require.Nil(t, resp)
	})

	t.Run("test get profile - invalid json", func(t *testing.T) {
		s := make(map[string][]byte)
		require.Equal(t, 0, len(s))

		profileStore, err := New(&mockstorage.Provider{Store: &mockstorage.MockStore{Store: s}})
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		s[getDBKey("issuer-1")] = []byte("invalid-data")

		resp, err := profileStore.GetProfile("issuer-1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, resp)
	})
}
