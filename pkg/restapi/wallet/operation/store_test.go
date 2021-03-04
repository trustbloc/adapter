/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation // nolint:testpackage // changing to different package requires exposing internal features.

import (
	"encoding/json"
	"fmt"
	"testing"

	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
)

const (
	sampleStoreErr    = "sample error"
	sampleUserID      = "userID-001"
	sampleInvID       = "invID-001"
	sampleConnID      = "connID-001"
	samplePreferences = "remote"
)

func TestNewWalletAppProfileStore(t *testing.T) {
	t.Run("create new wallet app profile store - success", func(t *testing.T) {
		store, err := newWalletAppProfileStore(&mockstorage.MockStoreProvider{})

		require.NoError(t, err)
		require.NotEmpty(t, store)
	})

	t.Run("create new wallet app profile store - failure", func(t *testing.T) {
		store, err := newWalletAppProfileStore(&mockstorage.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf(sampleStoreErr),
		})

		require.Error(t, err)
		require.Empty(t, store)
		require.Contains(t, err.Error(), "sample error")
	})
}

func TestWalletAppProfileStore_SaveInvitation(t *testing.T) {
	t.Run("save invitation - success", func(t *testing.T) {
		appProfileStore, err := newWalletAppProfileStore(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotEmpty(t, appProfileStore)

		err = appProfileStore.SaveInvitation(sampleInvID, sampleUserID)
		require.NoError(t, err)

		userIDBytes, err := appProfileStore.store.Get(getInvitationKeyPrefix(sampleInvID))
		require.NoError(t, err)
		require.Equal(t, sampleUserID, string(userIDBytes))
	})

	t.Run("save invitation - failure", func(t *testing.T) {
		provider := mockstorage.NewMockStoreProvider()
		provider.Store = &mockstorage.MockStore{
			ErrPut: fmt.Errorf(sampleStoreErr),
		}

		appProfileStore, err := newWalletAppProfileStore(provider)
		require.NoError(t, err)
		require.NotEmpty(t, appProfileStore)

		err = appProfileStore.SaveInvitation(sampleInvID, sampleUserID)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleStoreErr)
	})
}

func TestWalletAppProfileStore_SaveProfile(t *testing.T) {
	t.Run("save wallet app profile - success", func(t *testing.T) {
		appProfileStore, err := newWalletAppProfileStore(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotEmpty(t, appProfileStore)

		err = appProfileStore.SaveInvitation(sampleInvID, sampleUserID)
		require.NoError(t, err)

		err = appProfileStore.SaveProfile(sampleInvID, sampleConnID)
		require.NoError(t, err)

		userIDBytes, err := appProfileStore.store.Get(getInvitationKeyPrefix(sampleInvID))
		require.NoError(t, err)
		require.Equal(t, string(userIDBytes), sampleUserID)

		profileIDBytes, err := appProfileStore.store.Get(getUserIDKeyPrefix(sampleUserID))
		require.NoError(t, err)

		var profile walletAppProfile
		err = json.Unmarshal(profileIDBytes, &profile)
		require.NoError(t, err)
		require.Equal(t, profile.InvitationID, sampleInvID)
		require.Equal(t, profile.ConnectionID, sampleConnID)
	})

	t.Run("save wallet app profile - store failure", func(t *testing.T) {
		provider := mockstorage.NewMockStoreProvider()
		provider.Store = &mockstorage.MockStore{
			ErrPut: fmt.Errorf(sampleStoreErr),
			Store: map[string]mockstorage.DBEntry{
				getInvitationKeyPrefix(sampleInvID): {Value: []byte(sampleUserID)},
			},
		}

		appProfileStore, err := newWalletAppProfileStore(provider)
		require.NoError(t, err)
		require.NotEmpty(t, appProfileStore)

		err = appProfileStore.SaveProfile(sampleInvID, sampleConnID)
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleStoreErr)
	})

	t.Run("save wallet app profile - user info not found error", func(t *testing.T) {
		provider := mockstorage.NewMockStoreProvider()

		appProfileStore, err := newWalletAppProfileStore(provider)
		require.NoError(t, err)
		require.NotEmpty(t, appProfileStore)

		err = appProfileStore.SaveProfile(sampleInvID, sampleConnID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get user info for given invitation ID")
	})
}

func TestWalletAppProfileStore_Get(t *testing.T) {
	t.Run("get wallet app profile - success", func(t *testing.T) {
		appProfileStore, err := newWalletAppProfileStore(mockstorage.NewMockStoreProvider())

		require.NoError(t, err)
		require.NotEmpty(t, appProfileStore)

		userBytes, err := appProfileStore.GetUserByInvitationID(sampleInvID)
		require.Error(t, err)
		require.Empty(t, userBytes)
		require.Contains(t, err.Error(), "data not found")

		err = appProfileStore.SaveInvitation(sampleInvID, sampleUserID)
		require.NoError(t, err)

		profile, err := appProfileStore.GetProfileByUserID(sampleUserID)
		require.Error(t, err)
		require.Empty(t, profile)
		require.Contains(t, err.Error(), "failed to get wallet application profile by user ID")

		userBytes, err = appProfileStore.GetUserByInvitationID(sampleInvID)
		require.NoError(t, err)
		require.Equal(t, sampleUserID, string(userBytes))

		err = appProfileStore.SaveProfile(sampleInvID, sampleConnID)
		require.NoError(t, err)

		profile, err = appProfileStore.GetProfileByUserID(sampleUserID)
		require.NoError(t, err)
		require.Equal(t, profile.ConnectionID, sampleConnID)
		require.Equal(t, profile.InvitationID, sampleInvID)
	})

	t.Run("get wallet app profile  - failure - store error", func(t *testing.T) {
		provider := mockstorage.NewMockStoreProvider()
		provider.Store = &mockstorage.MockStore{
			ErrGet: fmt.Errorf(sampleStoreErr),
		}

		appProfileStore, err := newWalletAppProfileStore(provider)
		require.NoError(t, err)

		profile, err := appProfileStore.GetProfileByUserID(sampleUserID)
		require.Error(t, err)
		require.Empty(t, profile)
		require.Contains(t, err.Error(), sampleStoreErr)
	})

	t.Run("get wallet app profile  - failure - invalid data", func(t *testing.T) {
		provider := mockstorage.NewMockStoreProvider()
		provider.Store = &mockstorage.MockStore{
			Store: map[string]mockstorage.DBEntry{
				getUserIDKeyPrefix(sampleUserID): {Value: []byte("--")},
			},
		}

		appProfileStore, err := newWalletAppProfileStore(provider)
		require.NoError(t, err)

		profile, err := appProfileStore.GetProfileByUserID(sampleUserID)
		require.Error(t, err)
		require.Empty(t, profile)
		require.Contains(t, err.Error(), "failed to get wallet application profile bytes")
	})
}

func TestWalletAppProfileStore_putProfileInStore(t *testing.T) {
	t.Run("get wallet app profile  - failure - invalid data", func(t *testing.T) {
		appProfileStore, err := newWalletAppProfileStore(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		err = appProfileStore.putProfileInStore(getUserIDKeyPrefix, sampleUserID, make(chan int))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get wallet application profile bytes")
	})
}

func TestWalletAppProfileStore_Preferences(t *testing.T) {
	t.Run("wallet preferences success  - save & get ", func(t *testing.T) {
		appProfileStore, err := newWalletAppProfileStore(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		err = appProfileStore.SavePreferences(sampleUserID, []byte(samplePreferences))
		require.NoError(t, err)

		prefBytes, err := appProfileStore.GetPreferences(sampleUserID)
		require.NoError(t, err)
		require.Equal(t, string(prefBytes), samplePreferences)
	})

	t.Run("wallet preferences failure  - save & get", func(t *testing.T) {
		appProfileStore, err := newWalletAppProfileStore(&mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				ErrPut: fmt.Errorf(sampleErr),
				ErrGet: fmt.Errorf(sampleErr),
			},
		})
		require.NoError(t, err)

		err = appProfileStore.SavePreferences(sampleUserID, []byte(samplePreferences))
		require.Error(t, err)
		require.Equal(t, err.Error(), sampleErr)

		prefBytes, err := appProfileStore.GetPreferences(sampleUserID)
		require.Empty(t, prefBytes)
		require.Error(t, err)
		require.Equal(t, err.Error(), sampleErr)
	})
}
