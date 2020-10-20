/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
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
	VDRegistry() vdrapi.Registry
	Crypto() ariescrypto.Crypto
}
