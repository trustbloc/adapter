// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter/cmd/adapter-rest

go 1.14

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.5-0.20200904153313-0e08dc3311d4
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-adapter v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edge-core v0.1.4
)

replace github.com/trustbloc/edge-adapter => ../..

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e
