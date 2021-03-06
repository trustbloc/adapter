/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edge-adapter/pkg/profile/issuer"
	"github.com/trustbloc/edge-adapter/pkg/restapi/internal/common/oidc"
)

func Test_GetOIDCClient(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		mockOIDCServer := createMockOIDCServer("", "", "", "", fmt.Sprintf(
			`{"client_id":"example_client","client_secret":"abcdefg","client_secret_expires_at":%d}`,
			time.Now().Add(time.Hour*300).Unix()))

		defer mockOIDCServer.Close()

		err = op.saveOIDCClientData(mockOIDCServer.URL, &oidcClientData{
			ID:     "client-id",
			Secret: "client-secret",
			Expiry: 0,
		})
		require.NoError(t, err)

		_, err = op.getOIDCClient(mockOIDCServer.URL)
		require.NoError(t, err)
	})

	t.Run("success - cached client", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		op.cachedOIDCClients["provider.url"] = &oidc.Client{}

		_, err = op.getOIDCClient("provider.url")
		require.NoError(t, err)
	})

	t.Run("failure - client data missing", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		mockOIDCServer := createMockOIDCServer("", "", "", "", fmt.Sprintf(
			`{"client_id":"example_client","client_secret":"abcdefg","client_secret_expires_at":%d}`,
			time.Now().Add(time.Hour*300).Unix()))

		defer mockOIDCServer.Close()

		_, err = op.getOIDCClient(mockOIDCServer.URL)
		require.Error(t, err)
		require.ErrorIs(t, err, storage.ErrDataNotFound)
	})

	t.Run("failure - invalid provider url", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		err = op.saveOIDCClientData("~~~~", &oidcClientData{
			ID:     "client-id",
			Secret: "client-secret",
			Expiry: 0,
		})
		require.NoError(t, err)

		_, err = op.getOIDCClient("~~~~")
		require.Error(t, err)
		require.Contains(t, err.Error(), "constructing oidc client")
	})
}

func Test_CreateOIDCClient(t *testing.T) {
	t.Run("success: with multiple create calls", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		mockOIDCServer := createMockOIDCServer("", "", "", "", fmt.Sprintf(
			`{"client_id":"example_client","client_secret":"abcdefg","client_secret_expires_at":%d}`,
			time.Now().Add(time.Hour*300).Unix()))

		defer mockOIDCServer.Close()

		pd := issuer.ProfileData{
			ID:              "abcd",
			Name:            "issuer",
			OIDCProviderURL: mockOIDCServer.URL,
		}

		// call twice with the same issuer
		_, err = op.getOrCreateOIDCClient(&pd)
		require.NoError(t, err)

		_, err = op.getOrCreateOIDCClient(&pd)
		require.NoError(t, err)

		//	new ID but same oidc provider
		pd = issuer.ProfileData{
			ID:              "123abc",
			Name:            "issuer",
			OIDCProviderURL: mockOIDCServer.URL,
		}

		_, err = op.getOrCreateOIDCClient(&pd)
		require.NoError(t, err)
	})

	t.Run("success: bypassing client registration", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		mockOIDCServer := createMockOIDCServer("", "", "", "", "")

		defer mockOIDCServer.Close()

		pd := issuer.ProfileData{
			ID:              "abcd",
			Name:            "issuer",
			OIDCProviderURL: mockOIDCServer.URL,
			OIDCClientParams: &issuer.OIDCClientParams{
				ClientID:     "example_client",
				ClientSecret: "abcdefg",
				SecretExpiry: int(time.Now().Add(time.Hour * 300).Unix()),
			},
		}

		_, err = op.getOrCreateOIDCClient(&pd)
		require.NoError(t, err)
	})

	t.Run("success: with client data already stored", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		mockOIDCServer := createMockOIDCServer("", "", "", "", fmt.Sprintf(
			`{"client_id":"example_client","client_secret":"abcdefg","client_secret_expires_at":%d}`,
			time.Now().Add(time.Hour*300).Unix()))

		defer mockOIDCServer.Close()

		pd := issuer.ProfileData{
			ID:              "abcd",
			Name:            "issuer",
			OIDCProviderURL: mockOIDCServer.URL,
		}

		err = op.saveOIDCClientData(mockOIDCServer.URL, &oidcClientData{
			ID:     "client-id",
			Secret: "client-secret",
			Expiry: 0,
		})
		require.NoError(t, err)

		_, err = op.getOrCreateOIDCClient(&pd)
		require.NoError(t, err)
	})

	t.Run("failure: error checking store for client data", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		mockOIDCServer := createMockOIDCServer("", "", "", "", "")

		defer mockOIDCServer.Close()

		op.oidcClientStore = &mock.Store{
			ErrGet: fmt.Errorf("test err"),
		}

		pd := issuer.ProfileData{
			ID:              "abcd",
			Name:            "issuer",
			OIDCProviderURL: mockOIDCServer.URL,
		}

		_, err = op.getOrCreateOIDCClient(&pd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error getting client data")
	})

	t.Run("failure: error getting oidc provider configuration", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		badServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
		}))

		defer badServer.Close()

		pd := issuer.ProfileData{
			ID:              "abcd",
			Name:            "issuer",
			OIDCProviderURL: badServer.URL,
		}

		_, err = op.getOrCreateOIDCClient(&pd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error getting provider openid configuration")
	})

	t.Run("failure: error unmarshaling oidc provider configuration", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		badServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Write([]byte("this is not a json payload")) // nolint:errcheck,gosec
		}))

		defer badServer.Close()

		pd := issuer.ProfileData{
			ID:              "abcd",
			Name:            "issuer",
			OIDCProviderURL: badServer.URL,
		}

		_, err = op.getOrCreateOIDCClient(&pd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error getting provider openid configuration")
	})

	t.Run("failure: error registering with oidc provider", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		mockOIDCServer := createMockOIDCServer("", "", "", "", "")

		defer mockOIDCServer.Close()

		pd := issuer.ProfileData{
			ID:              "abcd",
			Name:            "issuer",
			OIDCProviderURL: mockOIDCServer.URL,
		}

		_, err = op.getOrCreateOIDCClient(&pd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error registering oidc client")
	})

	t.Run("failure: error saving registered client parameters", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		op.oidcClientStore = &mock.Store{
			ErrGet: storage.ErrDataNotFound,
			ErrPut: fmt.Errorf("test err"),
		}

		mockOIDCServer := createMockOIDCServer("", "", "", "", fmt.Sprintf(
			`{"client_id":"example_client","client_secret":"abcdefg","client_secret_expires_at":%d}`,
			time.Now().Add(time.Hour*300).Unix()))

		defer mockOIDCServer.Close()

		pd := issuer.ProfileData{
			ID:              "abcd",
			Name:            "issuer",
			OIDCProviderURL: mockOIDCServer.URL,
		}

		_, err = op.getOrCreateOIDCClient(&pd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error saving oidc client data")
	})

	t.Run("failure: error initializing oidc client", func(t *testing.T) {
		conf := config()

		op, err := New(conf)
		require.NoError(t, err)

		mockOIDCServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, e := writer.Write([]byte("{}"))
			require.NoError(t, e)
		}))

		defer mockOIDCServer.Close()

		pd := issuer.ProfileData{
			ID:              "abcd",
			Name:            "issuer",
			OIDCProviderURL: mockOIDCServer.URL,
			OIDCClientParams: &issuer.OIDCClientParams{
				ClientID:     "example_client",
				ClientSecret: "abcdefg",
				SecretExpiry: int(time.Now().Add(time.Hour * 300).Unix()),
			},
		}

		_, err = op.getOrCreateOIDCClient(&pd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating oidc client")
	})
}
