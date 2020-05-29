/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	mocksvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("test new - success", func(t *testing.T) {
		ariesCtx := &mockprovider.Provider{
			TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:          mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
			},
		}

		controller, err := New(ariesCtx)
		require.NoError(t, err)
		require.NotNil(t, controller)

		ops := controller.GetOperations()

		require.Equal(t, 1, len(ops))
	})

	t.Run("test new - fail", func(t *testing.T) {
		ariesCtx := &mockprovider.Provider{}

		controller, err := New(ariesCtx)
		require.Nil(t, controller)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create aries did exchange client")
	})
}
