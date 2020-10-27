/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package rp

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	ariesctx "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/trustbloc/edge-adapter/pkg/internal/mock/didexchange"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/messenger"
	mockpresentproof "github.com/trustbloc/edge-adapter/pkg/internal/mock/presentproof"
	"github.com/trustbloc/edge-adapter/pkg/restapi/rp/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := New(&operation.Config{
			DIDExchClient: &didexchange.MockClient{},
			Storage: &operation.Storage{
				Persistent: memstore.NewProvider(),
				Transient:  memstore.NewProvider(),
			},
			AriesContextProvider: agent(t),
			PresentProofClient:   &mockpresentproof.MockClient{},
			MsgRegistrar:         msghandler.NewRegistrar(),
			AriesMessenger:       &messenger.MockMessenger{},
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
		ops := controller.GetOperations()

		require.NotEmpty(t, ops)
	})
}

func agent(t *testing.T) *ariesctx.Provider {
	t.Helper()

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	return ctx
}
