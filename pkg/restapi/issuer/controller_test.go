/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	issuecredsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	mocksvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/trustbloc/edge-adapter/pkg/internal/mock/issuecredential"
	"github.com/trustbloc/edge-adapter/pkg/restapi/issuer/operation"
)

func TestNew(t *testing.T) {
	t.Run("test new - success", func(t *testing.T) {
		ariesCtx := &mockprovider.Provider{
			TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:          mockstore.NewMockStoreProvider(),
			ServiceMap: map[string]interface{}{
				didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
				mediator.Coordination:   &mockroute.MockMediatorSvc{},
				issuecredsvc.Name:       &issuecredential.MockIssueCredentialSvc{},
			},
		}

		controller, err := New(&operation.Config{
			AriesCtx:      ariesCtx,
			StoreProvider: memstore.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, controller)

		ops := controller.GetOperations()

		require.Equal(t, 5, len(ops))
	})

	t.Run("test new - fail", func(t *testing.T) {
		ariesCtx := &mockprovider.Provider{}

		controller, err := New(&operation.Config{AriesCtx: ariesCtx})
		require.Nil(t, controller)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create aries did exchange client")
	})
}
