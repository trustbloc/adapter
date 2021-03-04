/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"

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
		Store:             mem.NewProvider(),
		ConnectionLookup:  &mockconn.MockConnectionsLookup{ConnIDByDIDs: uuid.New().String()},
		MediatorSvc:       &mockroute.MockMediatorSvc{},
	}
}

func getDIDDoc() *did.Doc {
	return &did.Doc{
		Service: []did.Service{
			{
				ID:            uuid.New().String(),
				Type:          didCommServiceType,
				RecipientKeys: []string{"1ert5", "x5356s"},
			},
		},
	}
}
