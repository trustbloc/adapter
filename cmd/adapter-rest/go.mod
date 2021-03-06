// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter/cmd/adapter-rest

go 1.15

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.6
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210306194409-6e4c5d622fbc
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210306162754-1a1e0c4a378e
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210306162754-1a1e0c4a378e
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-adapter v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edge-core v0.1.6
)

replace github.com/trustbloc/edge-adapter => ../..
