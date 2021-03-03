/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"

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
	ID                          string            `json:"id,omitempty"`
	Name                        string            `json:"name"`
	URL                         string            `json:"url"`
	SupportedVCContexts         []string          `json:"supportedVCContexts"`
	SupportsAssuranceCredential bool              `json:"supportsAssuranceCredential"`
	RequiresBlindedRoute        bool              `json:"requiresBlindedRoute"`
	CredentialSigningKey        string            `json:"credentialSigningKey"`
	PresentationSigningKey      string            `json:"presentationSigningKey"`
	CreatedAt                   *time.Time        `json:"createdAt"`
	OIDCProviderURL             string            `json:"oidcProvider"`
	OIDCClientParams            *OIDCClientParams `json:"oidcParams,omitempty"`
}

// OIDCClientParams optional set of oidc client parameters that the issuer may set, for static client registration.
type OIDCClientParams struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	SecretExpiry int    `json:"SecretExpiry"`
}

// New returns new issuer profile instance.
func New(provider storage.Provider) (*Profile, error) {
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
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
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
		return nil, fmt.Errorf("get profile : %w", err)
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
		return fmt.Errorf("profile id mandatory")
	}

	if pr.Name == "" {
		return fmt.Errorf("profile name mandatory")
	}

	if len(pr.SupportedVCContexts) == 0 {
		return fmt.Errorf("supported vc contexts mandatory")
	}

	if !adapterutil.ValidHTTPURL(pr.URL) {
		return fmt.Errorf("issuer url is invalid")
	}

	return nil
}

func getDBKey(id string) string {
	return fmt.Sprintf(keyPattern, profileKeyPrefix, id)
}
