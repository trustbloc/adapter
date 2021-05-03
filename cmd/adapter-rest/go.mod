// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter/cmd/adapter-rest

go 1.16

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210427144858-06fb8b7d2d30
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210429200350-4099d2551ddd
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210422133815-2ef2d99cb692
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210422144621-1355c6f90b44
	github.com/piprate/json-gold v0.4.0
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-adapter v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edge-core v0.1.7-0.20210331113925-b13dedfe75eb
)

replace github.com/trustbloc/edge-adapter => ../..
