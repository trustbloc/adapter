/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package message

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	mockdidex "github.com/trustbloc/edge-adapter/pkg/internal/mock/didexchange"
	"github.com/trustbloc/edge-adapter/pkg/internal/mock/messenger"
)

func config() *Config {
	return &Config{
		DIDExchangeClient: &mockdidex.MockClient{},
		ServiceEndpoint:   "",
		AriesMessenger:    &messenger.MockMessenger{},
		MsgRegistrar:      msghandler.NewRegistrar(),
		VDRIRegistry:      &mockvdri.MockVDRIRegistry{},
		TransientStore:    memstore.NewProvider(),
	}
}
