// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter/cmd/adapter-rest

go 1.15

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/containerd/continuity v0.0.0-20200928162600-f2cc35102c2a // indirect
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210227013717-0ea0a23d87d3
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210305233053-d3d22c802c12
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210302153503-0e00e248f14d
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210302153503-0e00e248f14d
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-adapter v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edge-core v0.1.6-0.20210212172534-81ab3a5abf5b
)

replace github.com/trustbloc/edge-adapter => ../..
