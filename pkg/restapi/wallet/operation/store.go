/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	storageNamespace  = "walletappprofile"
	invitationKeyFmt  = "inv_%s"
	userIDKeyFmt      = "usr_%s"
	preferencesKeyFmt = "prfrnc_%s"
)

// walletAppProfile is wallet application profile.
type walletAppProfile struct {
	InvitationID string `json:"invitationID"`
	ConnectionID string `json:"connectionID"`
}

// walletAppProfileStore is wallet application profile store.
type walletAppProfileStore struct {
	store storage.Store
}

func newWalletAppProfileStore(p storage.Provider) (*walletAppProfileStore, error) {
	store, err := p.OpenStore(storageNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open wallet applcation profile store: %w", err)
	}

	return &walletAppProfileStore{store}, nil
}

// SaveInvitation saves mapping between invitation and userID
func (w *walletAppProfileStore) SaveInvitation(invitationID, userID string) error {
	logger.Debugf("invitationID=%s userID=%s", invitationID, userID)

	err := w.store.Put(getInvitationKeyPrefix(invitationID), []byte(userID))
	if err != nil {
		return fmt.Errorf("failed to save invitation: %w", err)
	}

	return nil
}

// SaveUserProfile saves wallet app profile by user ID.
func (w *walletAppProfileStore) SaveProfile(invitationID, connectionID string) error {
	userIDBytes, err := w.store.Get(getInvitationKeyPrefix(invitationID))
	if err != nil {
		return fmt.Errorf(
			"failed to get user info for given invitation ID [%s]: %w",
			invitationID, err)
	}

	err = w.putProfileInStore(getUserIDKeyPrefix, string(userIDBytes), &walletAppProfile{
		InvitationID: invitationID,
		ConnectionID: connectionID,
	})
	if err != nil {
		return fmt.Errorf("failed to save wallet application profile: %w", err)
	}

	return nil
}

// GetUserByInvitationID returns wallet profile user mapped for given invitation ID.
func (w *walletAppProfileStore) GetUserByInvitationID(invitationID string) ([]byte, error) {
	return w.store.Get(getInvitationKeyPrefix(invitationID)) // nolint:wrapcheck // reduce cyclo
}

// GetProfileByUserID returns wallet application profile by given user profile ID.
// returns error if no existing mapping found with any user profile.
func (w *walletAppProfileStore) GetProfileByUserID(userID string) (*walletAppProfile, error) {
	profileBytes, err := w.store.Get(getUserIDKeyPrefix(userID))
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet application profile by user ID: %w", err)
	}

	var profile walletAppProfile

	err = json.Unmarshal(profileBytes, &profile)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet application profile bytes: %w", err)
	}

	return &profile, nil
}

// SavePreferences saves user preferences bytes by user ID.
func (w *walletAppProfileStore) SavePreferences(userID string, preferences []byte) error {
	return w.store.Put(getPreferencesKeyPrefix(userID), preferences) // nolint:wrapcheck // reduce cyclo
}

// GetPreferences gets user preferences bytes by user ID.
func (w *walletAppProfileStore) GetPreferences(userID string) ([]byte, error) {
	return w.store.Get(getPreferencesKeyPrefix(userID)) // nolint:wrapcheck // reduce cyclo
}

func (w *walletAppProfileStore) putProfileInStore(prefix func(string) string, key string, profile interface{}) error {
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("failed to get wallet application profile bytes: %w", err)
	}

	return w.store.Put(prefix(key), profileBytes) // nolint:wrapcheck // reduce cyclo
}

// getInvitationKeyPrefix is key prefix for wallet application profile invitation key.
func getInvitationKeyPrefix(invitationID string) string {
	return fmt.Sprintf(invitationKeyFmt, invitationID)
}

// getUserIDKeyPrefix is key prefix for wallet application profile user ID key.
func getUserIDKeyPrefix(userID string) string {
	return fmt.Sprintf(userIDKeyFmt, userID)
}

func getPreferencesKeyPrefix(userID string) string {
	return fmt.Sprintf(preferencesKeyFmt, userID)
}
