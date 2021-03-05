/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/edge-adapter/pkg/profile/issuer"
	"github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/oidc"
)

func (o *Operation) getOIDCClient(providerURL string) (oidcClient, error) {
	if client, present := o.cachedOIDCClients[providerURL]; present {
		return client, nil
	}

	clientData, err := o.loadOIDCClientData(providerURL)
	if err != nil {
		return nil, fmt.Errorf("error loading oidc client data: %w", err)
	}

	client, err := oidc.New(&oidc.Config{
		TLSConfig:              o.tlsConfig,
		OIDCProviderURL:        providerURL,
		OIDCClientID:           clientData.ID,
		OIDCClientSecret:       clientData.Secret,
		OIDCClientSecretExpiry: clientData.Expiry,
		OIDCCallbackURL:        o.oidcCallbackURL,
		RefreshToken:           "", // TODO: load from refresh token store
	})
	if err != nil {
		return nil, fmt.Errorf("constructing oidc client: %w", err)
	}

	return client, nil
}

// getOrCreateOIDCClient returns an oidc client for a particular issuer.
// can recreate the client as needed - client data is persisted,
// and client is only registered if the persistent client data is not present.
func (o *Operation) getOrCreateOIDCClient(profileData *issuer.ProfileData) (oidcClient, error) {
	if client, present := o.cachedOIDCClients[profileData.OIDCProviderURL]; present {
		return client, nil
	}

	// TODO:
	//  - when using oidcClient, need to check if secret is expired

	clientData, err := o.getOrCreateClientData(profileData)
	if err != nil {
		return nil, err
	}

	client, err := oidc.New(&oidc.Config{
		TLSConfig:              o.tlsConfig,
		OIDCProviderURL:        profileData.OIDCProviderURL,
		OIDCClientID:           clientData.ID,
		OIDCClientSecret:       clientData.Secret,
		OIDCClientSecretExpiry: clientData.Expiry,
		OIDCCallbackURL:        o.oidcCallbackURL,
	})
	if err != nil {
		return nil, fmt.Errorf("creating oidc client: %w", err)
	}

	o.cachedOIDCClients[profileData.OIDCProviderURL] = client

	return client, nil
}

func (o *Operation) getOrCreateClientData(profileData *issuer.ProfileData) (*oidcClientData, error) {
	if profileData.OIDCClientParams != nil {
		return &oidcClientData{
			ID:     profileData.OIDCClientParams.ClientID,
			Secret: profileData.OIDCClientParams.ClientSecret,
			Expiry: profileData.OIDCClientParams.SecretExpiry,
		}, nil
	}

	clientData, err := o.loadOIDCClientData(profileData.OIDCProviderURL)
	if err == nil {
		return clientData, nil
	}

	if !errors.Is(err, storage.ErrDataNotFound) {
		return nil, fmt.Errorf("error getting client data: %w", err)
	}

	providerConfig, e := o.getOpenIDConfiguration(profileData.OIDCProviderURL)
	if e != nil {
		return nil, fmt.Errorf("error getting provider openid configuration: %w", e)
	}

	clientData, e = o.registerOAuthClient(providerConfig.Register)
	if e != nil {
		return nil, fmt.Errorf("error registering oidc client: %w", e)
	}

	e = o.saveOIDCClientData(profileData.OIDCProviderURL, clientData)
	if e != nil {
		return nil, fmt.Errorf("error saving oidc client data: %w", e)
	}

	return clientData, nil
}

type openidConfig struct {
	Issuer   string   `json:"issuer,omitempty"`
	Auth     string   `json:"authorization_endpoint"`
	Token    string   `json:"token_endpoint"`
	JWKs     string   `json:"jwks_uri"`
	UserInfo string   `json:"userinfo_endpoint"`
	Register string   `json:"registration_endpoint"`
	Algs     []string `json:"id_token_signing_alg_values_supported"`
}

func (o *Operation) getOpenIDConfiguration(providerURL string) (*openidConfig, error) {
	wellKnown := strings.TrimSuffix(providerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequest(http.MethodGet, wellKnown, bytes.NewReader(nil))
	if err != nil {
		return nil, err
	}

	respData, err := sendHTTPRequest(req, o.httpClient, http.StatusOK, "")
	if err != nil {
		return nil, fmt.Errorf("error response for openid configuration request: %w", err)
	}

	response := openidConfig{}

	err = json.Unmarshal(respData, &response)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling openID config: %w", err)
	}

	return &response, nil
}

type oidcClientRegisterRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
}

type oidcClientRegisterResponse struct {
	ID           string `json:"client_id"`
	Secret       string `json:"client_secret"`
	SecretExpiry int    `json:"client_secret_expires_at"`
}

// registerOAuthClient registers the issuer adapter as an OAuth2.0 client
// for the Oauth2.0 provider whose register endpoint is registerURL.
// Implements https://tools.ietf.org/html/rfc7591 (partially)
func (o *Operation) registerOAuthClient(registerURL string) (*oidcClientData, error) {
	reqData := oidcClientRegisterRequest{
		RedirectURIs:            []string{o.oidcCallbackURL},
		TokenEndpointAuthMethod: "client_secret_basic",
		Scope:                   "openid offline_access",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
	}

	reqBytes, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, registerURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}

	respData, err := sendHTTPRequest(req, o.httpClient, http.StatusCreated, "")
	if err != nil {
		return nil, fmt.Errorf("error response for register request: %w", err)
	}

	var response oidcClientRegisterResponse

	err = json.Unmarshal(respData, &response)
	if err != nil {
		return nil, err
	}

	return &oidcClientData{
		ID:     response.ID,
		Secret: response.Secret,
		Expiry: response.SecretExpiry,
	}, nil
}

type oidcClientDataWrapper struct {
	Nonce   []byte `json:"nonce"`
	Payload []byte `json:"pld"`
}

type oidcClientData struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
	Expiry int    `json:"exp"`
}

func (o *Operation) saveOIDCClientData(providerURL string, data *oidcClientData) error {
	wrappedBytes, err := encryptClientData(providerURL, o.oidcClientStoreKey, data)
	if err != nil {
		return fmt.Errorf("error encrypting client data: %w", err)
	}

	err = o.oidcClientStore.Put(providerURL, wrappedBytes)
	if err != nil {
		return fmt.Errorf("error storing client data: %w", err)
	}

	return nil
}

func (o *Operation) loadOIDCClientData(providerURL string) (*oidcClientData, error) {
	readBytes, err := o.oidcClientStore.Get(providerURL)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, err
		}

		return nil, fmt.Errorf("error loading client data: %w", err)
	}

	data, err := decryptClientData(o.oidcClientStoreKey, readBytes)
	if err != nil {
		return nil, fmt.Errorf("error decrypting client data: %w", err)
	}

	return data, nil
}

func encryptClientData(providerURL string, key []byte, data *oidcClientData) ([]byte, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error marshaling data: %w", err)
	}

	nonce, err := makeNonce([]byte(providerURL))
	if err != nil {
		return nil, fmt.Errorf("error generating nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM cipher: %w", err)
	}

	cipherText := gcm.Seal(nil, nonce, dataBytes, nil)

	dataWrapper := oidcClientDataWrapper{
		Nonce:   nonce,
		Payload: cipherText,
	}

	wrappedBytes, err := json.Marshal(dataWrapper)
	if err != nil {
		return nil, fmt.Errorf("error marshaling wrapper: %w", err)
	}

	return wrappedBytes, nil
}

func decryptClientData(key, readBytes []byte) (*oidcClientData, error) {
	wrapper := oidcClientDataWrapper{}

	err := json.Unmarshal(readBytes, &wrapper)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling wrapper: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM cipher: %w", err)
	}

	plainText, err := gcm.Open(nil, wrapper.Nonce, wrapper.Payload, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting client data: %w", err)
	}

	var data oidcClientData

	err = json.Unmarshal(plainText, &data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling client data: %w", err)
	}

	return &data, nil
}

// nolint:gochecknoglobals
var nonceCounter uint32 = 0

// generate a 12-byte AES GCM nonce by from a counter, timestamp, and additional mixin data
func makeNonce(data []byte) ([]byte, error) {
	sha := crypto.SHA256.New()

	timestamp, err := time.Now().MarshalBinary()
	if err != nil {
		return nil, err
	}

	_, err = sha.Write(timestamp)
	if err != nil {
		return nil, err
	}

	_, err = sha.Write(data)
	if err != nil {
		return nil, err
	}

	counter := atomic.AddUint32(&nonceCounter, 1)

	// nolint:gomnd
	sum := sha.Sum([]byte{
		byte(counter),
		byte(counter >> 8),
		byte(counter >> 16),
		byte(counter >> 24),
	})

	return sum[:12], nil
}
