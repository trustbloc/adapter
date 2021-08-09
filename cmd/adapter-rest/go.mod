// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter/cmd/adapter-rest

go 1.16

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go badfb20d82bec3e0154d49f2cf6072b8fcd72a21
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210630163721-35c6b2106c43
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210708130136-17663938344d
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210708130136-17663938344d
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-adapter v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edge-core v0.1.7-0.20210527163745-994ae929f957
)

replace github.com/trustbloc/edge-adapter => ../..
