/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("test new - success", func(t *testing.T) {
		t.Parallel()

		record, err := New(mem.NewProvider())
		require.NoError(t, err)
		require.NotNil(t, record)
	})

	t.Run("test new - fail to open store", func(t *testing.T) {
		t.Parallel()

		record, err := New(&mockstorage.Provider{ErrOpenStore: errors.New("error opening the handler")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error opening the handler")
		require.Nil(t, record)
	})
}

func TestCredentialRecord_SaveProfile(t *testing.T) {
	t.Parallel()

	t.Run("test save profile - success", func(t *testing.T) {
		t.Parallel()

		record, err := New(mem.NewProvider())
		require.NoError(t, err)
		require.NotNil(t, record)

		value := &ProfileData{
			ID:                  "profile1",
			Name:                "Issuer Profile 1",
			SupportedVCContexts: []string{"https://w3id.org/citizenship/v3"},
			URL:                 "http://issuer.example.com",
		}

		err = record.SaveProfile(value)
		require.NoError(t, err)

		k := getDBKey(value.ID)
		v, err := record.store.Get(k)
		require.NoError(t, err)
		require.NotEmpty(t, v)
	})

	t.Run("test save profile - validation failure", func(t *testing.T) {
		t.Parallel()

		record, err := New(mem.NewProvider())
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
		require.Contains(t, err.Error(), "issuer url is invalid")

		value.SupportsWACI = true
		err = record.SaveProfile(value)
		require.Error(t, err)
		require.Contains(t, err.Error(), "issuer id mandatory for waci profiles")
	})

	t.Run("test save profile - profile already exists", func(t *testing.T) {
		t.Parallel()

		record, err := New(mem.NewProvider())
		require.NoError(t, err)
		require.NotNil(t, record)

		value := &ProfileData{
			ID:                  "profile1",
			Name:                "Issuer Profile 1",
			SupportedVCContexts: []string{"https://w3id.org/citizenship/v3"},
			URL:                 "http://issuer.example.com",
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
	t.Parallel()

	t.Run("test get profile - success", func(t *testing.T) {
		t.Parallel()

		memProvider := mem.NewProvider()

		profileStore, err := New(memProvider)
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		profileData := &ProfileData{
			ID: "issuer-1",
		}

		profileJSON, err := json.Marshal(profileData)
		require.NoError(t, err)

		issuerStore, err := memProvider.OpenStore(storeName)
		require.NoError(t, err)

		err = issuerStore.Put(getDBKey(profileData.Name), profileJSON)
		require.NoError(t, err)

		resp, err := profileStore.GetProfile(profileData.Name)
		require.NoError(t, err)

		require.Equal(t, profileData, resp)
	})

	t.Run("test get profile - no data", func(t *testing.T) {
		t.Parallel()

		profileStore, err := New(mem.NewProvider())
		require.NoError(t, err)
		require.NotNil(t, profileStore)
		require.NotNil(t, profileStore)

		resp, err := profileStore.GetProfile("issuer-1")
		require.Error(t, err)
		require.Contains(t, err.Error(), storage.ErrDataNotFound.Error())
		require.Nil(t, resp)
	})

	t.Run("test get profile - invalid json", func(t *testing.T) {
		t.Parallel()

		memProvider := mem.NewProvider()

		profileStore, err := New(memProvider)
		require.NoError(t, err)
		require.NotNil(t, profileStore)

		issuerStore, err := memProvider.OpenStore(storeName)
		require.NoError(t, err)

		err = issuerStore.Put(getDBKey("issuer-1"), []byte("invalid-data"))
		require.NoError(t, err)

		resp, err := profileStore.GetProfile("issuer-1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, resp)
	})
}
