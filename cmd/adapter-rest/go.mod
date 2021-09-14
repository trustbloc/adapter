// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter/cmd/adapter-rest

go 1.16

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210819214613-1554e98c6f85
	github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb v0.0.0-20210913191140-6a8013cdda32
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210913191140-6a8013cdda32
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210913152107-80cff90741e9
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210913152107-80cff90741e9
	github.com/piprate/json-gold v0.4.1-0.20210813112359-33b90c4ca86c
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-adapter v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edge-core v0.1.7-0.20210816120552-ed93662ac716
)

replace github.com/trustbloc/edge-adapter => ../..
