/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package message

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	mockdidex "github.com/trustbloc/edge-adapter/pkg/internal/mock/didexchange"
	mockmediator "github.com/trustbloc/edge-adapter/pkg/internal/mock/mediator"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/messenger"
)

func config() *Config {
	return &Config{
		DIDExchangeClient: &mockdidex.MockClient{},
		MediatorClient:    &mockmediator.MockClient{},
		ServiceEndpoint:   "",
		AriesMessenger:    &messenger.MockMessenger{},
		MsgRegistrar:      msghandler.NewRegistrar(),
		VDRIRegistry:      &mockvdr.MockVDRegistry{},
		TransientStore:    memstore.NewProvider(),
	}
}
