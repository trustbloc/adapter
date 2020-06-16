/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aries

import (
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// CtxProvider contains dependencies to create aries protocol clients and is typically created by using aries.Context().
type CtxProvider interface {
	Service(id string) (interface{}, error)
	LegacyKMS() legacykms.KeyManager
	ServiceEndpoint() string
	StorageProvider() storage.Provider
	TransientStorageProvider() storage.Provider
	KMS() kms.KeyManager
}
