/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	outofbandsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	mocksvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	ariesmockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	mockoutofband "github.com/trustbloc/edge-adapter/pkg/internal/mock/outofband"
	mockprovider "github.com/trustbloc/edge-adapter/pkg/restapi/internal/mocks/provider"
	"github.com/trustbloc/edge-adapter/pkg/restapi/wallet/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := New(&operation.Config{
			AriesCtx: &mockprovider.MockProvider{
				Provider: &ariesmockprovider.Provider{
					StorageProviderValue:              mockstore.NewMockStoreProvider(),
					ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
					ServiceMap: map[string]interface{}{
						didexchange.DIDExchange: &mocksvc.MockDIDExchangeSvc{},
						outofbandsvc.Name:       &mockoutofband.MockService{},
						mediator.Coordination:   &mockroute.MockMediatorSvc{},
					},
				},
			},
			MsgRegistrar: msghandler.NewRegistrar(),
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
		ops := controller.GetOperations()

		require.NotEmpty(t, ops)
	})
}
