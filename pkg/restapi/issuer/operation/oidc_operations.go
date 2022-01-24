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

func (o *Operation) getOIDCClient(issuerID, providerURL string) (oidcClient, error) {
	if client, present := o.cachedOIDCClients[issuerID]; present {
		return client, nil
	}

	clientData, err := o.loadOIDCClientData(issuerID)
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
		Scopes:                 clientData.Scopes,
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
	if client, present := o.cachedOIDCClients[profileData.ID]; present {
		// TODO: should check whether client secret is expired
		return client, nil
	}

	// TODO: when creating an oidcClient, need to check if secret is expired

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
		Scopes:                 clientData.Scopes,
	})
	if err != nil {
		return nil, fmt.Errorf("creating oidc client: %w", err)
	}

	o.cachedOIDCClients[profileData.ID] = client

	return client, nil
}

func (o *Operation) getOrCreateClientData(profileData *issuer.ProfileData) (*oidcClientData, error) {
	if profileData.OIDCClientParams != nil {
		return &oidcClientData{
			ID:     profileData.OIDCClientParams.ClientID,
			Secret: profileData.OIDCClientParams.ClientSecret,
			Expiry: profileData.OIDCClientParams.SecretExpiry,
			Scopes: append([]string{"openid", "offline_access"}, profileData.CredentialScopes...),
		}, nil
	}

	clientData, err := o.loadOIDCClientData(profileData.ID)
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

	clientData, e = o.registerOAuthClient(providerConfig.Register, profileData)
	if e != nil {
		return nil, fmt.Errorf("error registering oidc client: %w", e)
	}

	e = o.saveOIDCClientData(profileData.ID, clientData)
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
		return nil, fmt.Errorf("failed to create http request: %w", err)
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
	Name                    string   `json:"client_name,omitempty"`
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
func (o *Operation) registerOAuthClient(registerURL string, profileData *issuer.ProfileData) (*oidcClientData, error) {
	scopes := []string{"openid", "offline_access"}
	name := ""

	if profileData != nil {
		name = profileData.Name

		scopes = append(scopes, profileData.CredentialScopes...)
	}

	reqData := oidcClientRegisterRequest{
		Name:                    name,
		RedirectURIs:            []string{o.oidcCallbackURL},
		TokenEndpointAuthMethod: "client_secret_basic",
		Scope:                   strings.Join(scopes, " "),
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
	}

	reqBytes, err := json.Marshal(reqData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request data: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, registerURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	respData, err := sendHTTPRequest(req, o.httpClient, http.StatusCreated, "")
	if err != nil {
		return nil, fmt.Errorf("error response for register request: %w", err)
	}

	var response oidcClientRegisterResponse

	err = json.Unmarshal(respData, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &oidcClientData{
		ID:     response.ID,
		Secret: response.Secret,
		Expiry: response.SecretExpiry,
		Scopes: scopes,
	}, nil
}

type oidcClientDataWrapper struct {
	Nonce   []byte `json:"nonce"`
	Payload []byte `json:"pld"`
}

type oidcClientData struct {
	ID     string   `json:"id"`
	Secret string   `json:"secret"`
	Expiry int      `json:"exp"`
	Scopes []string `json:"credScopes,omitempty"`
}

func (o *Operation) saveOIDCClientData(issuerProfileID string, data *oidcClientData) error {
	wrappedBytes, err := encryptClientData(issuerProfileID, o.oidcClientStoreKey, data)
	if err != nil {
		return fmt.Errorf("error encrypting client data: %w", err)
	}

	err = o.oidcClientStore.Put(issuerProfileID, wrappedBytes)
	if err != nil {
		return fmt.Errorf("error storing client data: %w", err)
	}

	return nil
}

func (o *Operation) loadOIDCClientData(issuerProfileID string) (*oidcClientData, error) {
	readBytes, err := o.oidcClientStore.Get(issuerProfileID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, fmt.Errorf("failed to fetch oidc client data: %w", err)
		}

		return nil, fmt.Errorf("error loading client data: %w", err)
	}

	data, err := decryptClientData(o.oidcClientStoreKey, readBytes)
	if err != nil {
		return nil, fmt.Errorf("error decrypting client data: %w", err)
	}

	return data, nil
}

func encryptClientData(id string, key []byte, data *oidcClientData) ([]byte, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error marshaling data: %w", err)
	}

	nonce, err := makeNonce([]byte(id))
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
var nonceCounter uint32

// generate a 12-byte AES GCM nonce by from a counter, timestamp, and additional mixin data
func makeNonce(data []byte) ([]byte, error) {
	sha := crypto.SHA256.New()

	timestamp, err := time.Now().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal timestamp: %w", err)
	}

	_, err = sha.Write(timestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to write timestamp to hash function: %w", err)
	}

	_, err = sha.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to hash function: %w", err)
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
