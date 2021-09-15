/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// DIDExStateComp state complete message type.
	DIDExStateComp = "https://trustbloc.dev/didexchange/1.0/state-complete"
)

// CtxProvider contains dependencies to create aries protocol clients and is typically created by using aries.Context().
type CtxProvider interface {
	Service(id string) (interface{}, error)
	ServiceEndpoint() string
	StorageProvider() storage.Provider
	Messenger() service.Messenger
	ProtocolStateStorageProvider() storage.Provider
	KMS() kms.KeyManager
	VDRegistry() vdrapi.Registry
	Crypto() ariescrypto.Crypto
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
	MediaTypeProfiles() []string
}

// DIDCommMsg core didcomm message model.
type DIDCommMsg struct {
	ID   string `json:"@id"`
	Type string `json:"@type"`
}
