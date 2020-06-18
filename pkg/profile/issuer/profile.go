/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edge-adapter/pkg/internal/common/adapterutil"
)

const (
	keyPattern       = "%s_%s"
	profileKeyPrefix = "profile"

	storeName = "issuer"
)

// Profile db operation.
type Profile struct {
	store storage.Store
}

// ProfileData struct for profile.
type ProfileData struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	CallbackURL string `json:"callbackURL"`
}

// New returns new issuer profile instance.
func New(provider storage.Provider) (*Profile, error) {
	err := provider.CreateStore(storeName)
	if err != nil && err != storage.ErrDuplicateStore {
		return nil, err
	}

	store, err := provider.OpenStore(storeName)
	if err != nil {
		return nil, err
	}

	return &Profile{store: store}, nil
}

// SaveProfile saves the profile data.
func (c *Profile) SaveProfile(data *ProfileData) error {
	// validate the profile
	if err := validateProfileRequest(data); err != nil {
		return err
	}

	// verify profile exists
	profile, err := c.GetProfile(data.ID)
	if err != nil && !errors.Is(err, storage.ErrValueNotFound) {
		return err
	}

	if profile != nil {
		return fmt.Errorf("profile %s already exists", profile.ID)
	}

	// save the profile
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("issuer profile save - marshalling error: %s", err.Error())
	}

	return c.store.Put(getDBKey(data.ID), bytes)
}

// GetProfile retrieves the profile data based on id.
func (c *Profile) GetProfile(id string) (*ProfileData, error) {
	bytes, err := c.store.Get(getDBKey(id))
	if err != nil {
		return nil, err
	}

	response := &ProfileData{}

	err = json.Unmarshal(bytes, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func validateProfileRequest(pr *ProfileData) error {
	if pr.ID == "" {
		return fmt.Errorf("missing profile id")
	}

	if pr.Name == "" {
		return fmt.Errorf("missing profile name")
	}

	if !adapterutil.ValidHTTPURL(pr.CallbackURL) {
		return fmt.Errorf("callback url is invalid")
	}

	return nil
}

func getDBKey(id string) string {
	return fmt.Sprintf(keyPattern, profileKeyPrefix, id)
}
