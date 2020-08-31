/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// CtxProvider contains dependencies to create aries protocol clients and is typically created by using aries.Context().
type CtxProvider interface {
	Service(id string) (interface{}, error)
	ServiceEndpoint() string
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	KMS() kms.KeyManager
	VDRIRegistry() vdriapi.Registry
	Crypto() ariescrypto.Crypto
}
