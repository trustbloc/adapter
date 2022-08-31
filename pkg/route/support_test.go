/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/stretchr/testify/require"

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
		KeyManager:        &mockkms.KeyManager{},
		KeyType:           kms.ED25519Type,
		KeyAgrType:        kms.ED25519Type,
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

type mockKMSProvider struct {
	store             kms.Store
	secretLockService secretlock.Service
}

func (m *mockKMSProvider) StorageProvider() kms.Store {
	return m.store
}

func (m *mockKMSProvider) SecretLock() secretlock.Service {
	return m.secretLockService
}

func realKMS(t *testing.T) kms.KeyManager {
	t.Helper()

	kmsStore, err := kms.NewAriesProviderWrapper(mockstore.NewMockStoreProvider())
	require.NoError(t, err)

	ctx := &mockKMSProvider{
		store:             kmsStore,
		secretLockService: &noop.NoLock{},
	}

	keyManager, err := localkms.New("prefixname://test.kms", ctx)
	require.NoError(t, err)

	return keyManager
}
