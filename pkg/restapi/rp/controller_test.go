/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package rp

import (
	"testing"

	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/trustbloc/edge-adapter/pkg/internal/mock/didexchange"
	mockpresentproof "github.com/trustbloc/edge-adapter/pkg/internal/mock/presentproof"
	"github.com/trustbloc/edge-adapter/pkg/restapi/rp/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := New(&operation.Config{
			DIDExchClient:        &didexchange.MockClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesContextProvider{},
			PresentProofClient:   &mockpresentproof.MockClient{},
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
		ops := controller.GetOperations()

		require.Equal(t, 7, len(ops))
	})
}

type mockAriesContextProvider struct {
	store   ariesstorage.Provider
	tstore  ariesstorage.Provider
	vdriReg vdriapi.Registry
}

func (m *mockAriesContextProvider) StorageProvider() ariesstorage.Provider {
	if m.store != nil {
		return m.store
	}

	return ariesmockstorage.NewMockStoreProvider()
}

func (m *mockAriesContextProvider) ProtocolStateStorageProvider() ariesstorage.Provider {
	if m.tstore != nil {
		return m.tstore
	}

	return ariesmockstorage.NewMockStoreProvider()
}

func (m *mockAriesContextProvider) VDRIRegistry() vdriapi.Registry {
	return m.vdriReg
}
