/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		mockOIDCData := ""

		mockOIDCServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, e := w.Write([]byte(mockOIDCData))
			require.NoError(t, e)
		}))

		t.Cleanup(mockOIDCServer.Close)

		mockOIDCData = fmt.Sprintf(`{
    "issuer":"%s",
    "authorization_endpoint":"%s/authorize",
    "token_endpoint":"%s/token",
    "jwks_uri":"%s/jwk",
    "userinfo_endpoint":"%s/userinfo",
    "id_token_signing_alg_values_supported":["ES256"]
}`, mockOIDCServer.URL, mockOIDCServer.URL, mockOIDCServer.URL, mockOIDCServer.URL, mockOIDCServer.URL)

		o, err := New(&Config{
			TLSConfig:        nil,
			OIDCProviderURL:  mockOIDCServer.URL,
			OIDCClientID:     "abcd",
			OIDCClientSecret: "ab cd ef gh ij kl mn op qr st uv wx yz",
			OIDCCallbackURL:  "http://localhost/abcde",
		})

		require.NoError(t, err)
		require.Equal(t, mockOIDCServer.URL+"/authorize", o.oidcProvider.Endpoint().AuthURL)
	})

	t.Run("failure - bad provider url", func(t *testing.T) {
		t.Parallel()

		_, err := New(&Config{
			TLSConfig:        nil,
			OIDCProviderURL:  "badurl",
			OIDCClientID:     "abcd",
			OIDCClientSecret: "ab cd ef gh ij kl mn op qr st uv wx yz",
			OIDCCallbackURL:  "http://localhost/abcde",
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to init oidc provider with url")
	})
}

func TestClient_CreateOIDCRequest(t *testing.T) {
	t.Parallel()

	mockOIDCData := ""

	mockOIDCServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, e := w.Write([]byte(mockOIDCData))
		require.NoError(t, e)
	}))

	t.Cleanup(mockOIDCServer.Close)

	mockOIDCData = fmt.Sprintf(`{
    "issuer":"%s",
    "authorization_endpoint":"%s/authorize",
    "token_endpoint":"%s/token",
    "jwks_uri":"%s/jwk",
    "userinfo_endpoint":"%s/userinfo",
    "id_token_signing_alg_values_supported":["ES256"]
}`, mockOIDCServer.URL, mockOIDCServer.URL, mockOIDCServer.URL, mockOIDCServer.URL, mockOIDCServer.URL)

	o, err := New(&Config{
		TLSConfig:        nil,
		OIDCProviderURL:  mockOIDCServer.URL,
		OIDCClientID:     "abcd",
		OIDCClientSecret: "ab cd ef gh ij kl mn op qr st uv wx yz",
		OIDCCallbackURL:  "http://localhost/abcde",
		Scopes:           []string{"scopescopescope"},
	})

	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		reqURL := o.CreateOIDCRequest("stateDataStateDataState", "scopescopescope")
		require.Contains(t, reqURL, mockOIDCServer.URL+"/authorize")
		require.Contains(t, reqURL, "stateDataStateDataState")
		require.Contains(t, reqURL, "scopescopescope")
	})
}

type idTokenJSONType struct {
	Issuer       string            `json:"iss,omitempty"`
	Subject      string            `json:"sub,omitempty"`
	Audience     []string          `json:"aud,omitempty"`
	Expiry       int64             `json:"exp,omitempty"`
	IssuedAt     int64             `json:"iat,omitempty"`
	Nonce        string            `json:"nonce,omitempty"`
	AtHash       string            `json:"at_hash,omitempty"`
	ClaimNames   map[string]string `json:"_claim_names,omitempty"`
	ClaimSources map[string]struct {
		Endpoint    string `json:"endpoint,omitempty"`
		AccessToken string `json:"access_token,omitempty"`
	} `json:"_claim_sources,omitempty"`
}

func TestClient_GetIDTokenClaims(t *testing.T) { // nolint:tparallel // data race
	t.Parallel()

	sigPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sigPub := sigPriv.Public()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: sigPriv}, nil)
	require.NoError(t, err)

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       sigPub,
				Algorithm: "ES256",
			},
		},
	}

	mockServerData := struct {
		Config []byte
		Token  []byte
		JWKSet []byte
	}{
		[]byte(""),
		[]byte(""),
		[]byte(""),
	}

	mockServerData.JWKSet, err = json.Marshal(jwks)
	require.NoError(t, err)

	mockOIDCServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.Contains(p, ".well-known/openid-configuration"):
			_, e := w.Write(mockServerData.Config)
			require.NoError(t, e)
		case strings.Contains(p, "token"):
			w.Header().Set("Content-Type", "application/json")
			_, e := w.Write(mockServerData.Token)
			require.NoError(t, e)
		case strings.Contains(p, "jwk_endpoint"):
			w.Header().Set("Content-Type", "application/json")
			_, e := w.Write(mockServerData.JWKSet)
			require.NoError(t, e)
		}
	}))

	t.Cleanup(mockOIDCServer.Close)

	mockServerData.Config = []byte(fmt.Sprintf(`{
    "issuer":"%s",
    "authorization_endpoint":"%s/authorize",
    "token_endpoint":"%s/token",
    "jwks_uri":"%s/jwk_endpoint",
    "userinfo_endpoint":"%s/userinfo",
    "id_token_signing_alg_values_supported":["ES256","EdDSA"]
}`, mockOIDCServer.URL, mockOIDCServer.URL, mockOIDCServer.URL, mockOIDCServer.URL, mockOIDCServer.URL))

	idTok := idTokenJSONType{
		Issuer:   mockOIDCServer.URL,
		Audience: []string{"abcd"},
		Subject:  "",
		Expiry:   time.Now().Add(time.Hour).Unix(),
		IssuedAt: time.Now().Unix(),
		Nonce:    "",
		AtHash:   "",
	}

	idTokBytes, err := json.Marshal(idTok)
	require.NoError(t, err)

	sig, err := signer.Sign(idTokBytes)
	require.NoError(t, err)
	sigCompact, err := sig.CompactSerialize()
	require.NoError(t, err)

	mockServerData.Token = []byte(
		`{"access_token":"tokenTokenTokenToken","token_type":"bearer","id_token":"` + sigCompact + `"}`)

	o, err := New(&Config{
		TLSConfig:        nil,
		OIDCProviderURL:  mockOIDCServer.URL,
		OIDCClientID:     "abcd",
		OIDCClientSecret: "ab cd ef gh ij kl mn op qr st uv wx yz",
		OIDCCallbackURL:  "http://localhost/abcde",
	})
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) { // nolint:paralleltest // data race
		_, err := o.GetIDTokenClaims(context.TODO(), "blahblah")
		require.NoError(t, err)
	})

	t.Run("failure - exchanging oauth code for token", func(t *testing.T) { // nolint:paralleltest // data race
		goodToken := mockServerData.Token
		mockServerData.Token = nil

		_, err := o.GetIDTokenClaims(context.TODO(), "blahblah")
		require.Error(t, err)
		require.Contains(t, err.Error(), "exchange oauth2 code for token")

		mockServerData.Token = goodToken
	})

	t.Run("failure - missing id_token", func(t *testing.T) { // nolint:paralleltest // data race
		goodToken := mockServerData.Token
		mockServerData.Token = []byte(`{"access_token":"tokenTokenTokenToken","token_type":"bearer"}`)

		_, err := o.GetIDTokenClaims(context.TODO(), "blahblah")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing id_token")

		mockServerData.Token = goodToken
	})

	t.Run("failure - verifying id_token", func(t *testing.T) { // nolint:paralleltest // data race
		goodToken := mockServerData.Token
		mockServerData.Token = []byte(`{"access_token":"tokenTokenTokenToken","token_type":"bearer","id_token":"abcd"}`)

		_, err := o.GetIDTokenClaims(context.TODO(), "blahblah")
		require.Error(t, err)
		require.Contains(t, err.Error(), "verify id_token")

		mockServerData.Token = goodToken
	})
}

func TestClient_CheckRefresh(t *testing.T) { // nolint:tparallel // data race
	t.Parallel()

	mockServerData := struct {
		Config []byte
		Token  []byte
		JWKSet []byte
	}{
		[]byte(""),
		[]byte(""),
		[]byte(""),
	}

	mockOIDCServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.Contains(p, ".well-known/openid-configuration"):
			_, e := w.Write(mockServerData.Config)
			require.NoError(t, e)
		case strings.Contains(p, "token"):
			w.Header().Set("Content-Type", "application/json")
			_, e := w.Write(mockServerData.Token)
			require.NoError(t, e)
		case strings.Contains(p, "jwk_endpoint"):
			w.Header().Set("Content-Type", "application/json")
			_, e := w.Write(mockServerData.JWKSet)
			require.NoError(t, e)
		}
	}))

	t.Cleanup(mockOIDCServer.Close)

	mockServerData.Config = []byte(fmt.Sprintf(`{
    "issuer":"%s",
    "authorization_endpoint":"%s/authorize",
    "token_endpoint":"%s/token",
    "jwks_uri":"%s/jwk_endpoint",
    "userinfo_endpoint":"%s/userinfo",
    "id_token_signing_alg_values_supported":["ES256","EdDSA"]
}`, mockOIDCServer.URL, mockOIDCServer.URL, mockOIDCServer.URL, mockOIDCServer.URL, mockOIDCServer.URL))

	o, err := New(&Config{
		TLSConfig:        nil,
		OIDCProviderURL:  mockOIDCServer.URL,
		OIDCClientID:     "abcd",
		OIDCClientSecret: "ab cd ef gh ij kl mn op qr st uv wx yz",
		OIDCCallbackURL:  "http://localhost/abcde",
	})
	require.NoError(t, err)

	t.Run("success - no refresh", func(t *testing.T) { // nolint:paralleltest // data race
		tok := oauth2.Token{AccessToken: "abcd", RefreshToken: "abcd"}

		_, err := o.CheckRefresh(&tok)
		require.NoError(t, err)
	})

	t.Run("success - must refresh", func(t *testing.T) { // nolint:paralleltest // data race
		tok := oauth2.Token{RefreshToken: "abcd"}

		mockServerData.Token = []byte(`{
	"access_token":"abcd",
	"refresh_token":"abcd"
}`)

		_, err := o.CheckRefresh(&tok)
		require.NoError(t, err)
	})

	t.Run("failure - missing refresh token on expired token", func(t *testing.T) { // nolint:paralleltest // data race
		tok := oauth2.Token{AccessToken: "abcd", Expiry: time.Unix(0, 0)}

		mockServerData.Token = []byte(`{
	"access_token":"abcd",
	"refresh_token":"abcd"
}`)

		_, err := o.CheckRefresh(&tok)
		require.Error(t, err)
	})
}
