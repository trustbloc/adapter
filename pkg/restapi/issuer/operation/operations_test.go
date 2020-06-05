/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trustbloc/edge-adapter/pkg/aries"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	mocksvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("test new - success", func(t *testing.T) {
		c, err := New(&Config{AriesCtx: getAriesCtx()})
		require.NoError(t, err)

		require.Equal(t, 2, len(c.GetRESTHandlers()))
	})

	t.Run("test new - fail", func(t *testing.T) {
		c, err := New(&Config{AriesCtx: &mockprovider.Provider{}})
		require.Nil(t, c)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create aries did exchange client")
	})
}

func TestConnectWallet(t *testing.T) {
	t.Run("test connect wallet - success", func(t *testing.T) {
		c, err := New(&Config{AriesCtx: getAriesCtx()})
		require.NoError(t, err)

		walletConnectHandler := getHandler(t, c, walletConnectEndpoint)

		rr := serveHTTP(t, walletConnectHandler.Handle(), http.MethodGet, generateInvitationEndpoint, nil)

		require.Equal(t, http.StatusFound, rr.Code)
	})
}

func TestGenerateInvitation(t *testing.T) {
	t.Run("test new - success", func(t *testing.T) {
		c, err := New(&Config{AriesCtx: getAriesCtx()})
		require.NoError(t, err)

		generateInvitationHandler := getHandler(t, c, generateInvitationEndpoint)

		rr := serveHTTP(t, generateInvitationHandler.Handle(), http.MethodGet, generateInvitationEndpoint, nil)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("test new - error", func(t *testing.T) {
		ariesCtx := &mockprovider.Provider{
			TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:          mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
			LegacyKMSValue:       &mockkms.CloseableKMS{CreateKeyErr: errors.New("key generation error")},
			ServiceEndpointValue: "endpoint",
		}

		c, err := New(&Config{AriesCtx: ariesCtx})
		require.NoError(t, err)

		generateInvitationHandler := getHandler(t, c, generateInvitationEndpoint)

		rr := serveHTTP(t, generateInvitationHandler.Handle(), http.MethodGet, generateInvitationEndpoint, nil)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create invitation")
	})
}

func getAriesCtx() aries.CtxProvider {
	return &mockprovider.Provider{
		TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:          mockstore.NewMockStoreProvider(),
		ServiceMap: map[string]interface{}{
			didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
			mediator.Coordination:   &mockroute.MockMediatorSvc{},
		},
		LegacyKMSValue:       &mockkms.CloseableKMS{CreateEncryptionKeyValue: "sample-key"},
		ServiceEndpointValue: "endpoint",
	}
}

func getHandler(t *testing.T, op *Operation, lookup string) Handler {
	return getHandlerWithError(t, op, lookup)
}

func getHandlerWithError(t *testing.T, op *Operation, lookup string) Handler {
	return handlerLookup(t, op, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func serveHTTP(t *testing.T, handler http.HandlerFunc, method, path string, req []byte) *httptest.ResponseRecorder {
	httpReq, err := http.NewRequest(
		method,
		path,
		bytes.NewBuffer(req),
	)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, httpReq)

	return rr
}
