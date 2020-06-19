/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package rp

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/trustbloc/edge-adapter/pkg/restapi/rp/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := New(&operation.Config{
			DIDExchClient:        &stubDIDClient{},
			Store:                memstore.NewProvider(),
			AriesStorageProvider: &mockAriesStorageProvider{},
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
		ops := controller.GetOperations()

		require.Equal(t, 7, len(ops))
	})
}

type stubDIDClient struct {
}

func (s *stubDIDClient) RegisterActionEvent(chan<- service.DIDCommAction) error {
	return nil
}

func (s *stubDIDClient) RegisterMsgEvent(chan<- service.StateMsg) error {
	return nil
}

func (s *stubDIDClient) CreateInvitationWithDID(string, string) (*didexchange.Invitation, error) {
	return nil, nil
}

type mockAriesStorageProvider struct {
	store  ariesstorage.Provider
	tstore ariesstorage.Provider
}

func (m *mockAriesStorageProvider) StorageProvider() ariesstorage.Provider {
	if m.store != nil {
		return m.store
	}

	return ariesmockstorage.NewMockStoreProvider()
}

func (m *mockAriesStorageProvider) TransientStorageProvider() ariesstorage.Provider {
	if m.tstore != nil {
		return m.tstore
	}

	return ariesmockstorage.NewMockStoreProvider()
}
