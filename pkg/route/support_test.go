/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	mockconn "github.com/trustbloc/edge-adapter/pkg/internal/mock/connection"
	mockdidex "github.com/trustbloc/edge-adapter/pkg/internal/mock/didexchange"
	mockmediator "github.com/trustbloc/edge-adapter/pkg/internal/mock/mediator"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/messenger"
)

func config() *Config {
	return &Config{
		DIDExchangeClient: &mockdidex.MockClient{},
		MediatorClient:    &mockmediator.MockClient{},
		ServiceEndpoint:   "http://adapter.com",
		AriesMessenger:    &messenger.MockMessenger{},
		MsgRegistrar:      msghandler.NewRegistrar(),
		VDRIRegistry:      &mockvdr.MockVDRegistry{},
		TransientStore:    memstore.NewProvider(),
		ConnectionLookup:  &mockconn.MockConnectionsLookup{ConnIDByDIDs: uuid.New().String()},
	}
}
