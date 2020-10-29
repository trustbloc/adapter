// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter/cmd/adapter-rest

go 1.15

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201022202135-f8f69217453b
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20201020112434-8a30c982a980
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-adapter v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edge-core v0.1.5-0.20200916124536-c32454a16108
)

replace (
	github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201008080608-ba2e87ef05ef
	github.com/phoreproject/bls => github.com/trustbloc/bls v0.0.0-20201008085849-81064514c3cc
	github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e
	github.com/trustbloc/edge-adapter => ../..
)
