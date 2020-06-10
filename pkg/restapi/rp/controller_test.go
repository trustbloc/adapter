/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package rp

import (
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/trustbloc/edge-adapter/pkg/restapi/rp/operation"
)

func TestController_New(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		controller, err := New(&operation.Config{
			DIDExchClient: &stubDIDClient{},
			Store:         memstore.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, controller)
		ops := controller.GetOperations()

		require.Equal(t, 6, len(ops))
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
