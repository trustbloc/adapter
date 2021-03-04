// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter

go 1.15

require (
	github.com/PaesslerAG/gval v1.1.0
	github.com/PaesslerAG/jsonpath v0.1.1
	github.com/cenkalti/backoff/v4 v4.1.0 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210227013717-0ea0a23d87d3
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210303194824-a55a12f8d063 // indirect
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210303194824-a55a12f8d063
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210303194824-a55a12f8d063
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210302153503-0e00e248f14d
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210227013717-0ea0a23d87d3
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/ory/hydra-client-go v1.4.10
	github.com/piprate/json-gold v0.3.1-0.20201222165305-f4ce31c02ca3
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.6-0.20210212172534-81ab3a5abf5b
	golang.org/x/oauth2 v0.0.0-20200902213428-5d25da1a8d43
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/square/go-jose.v2 v2.5.1
)
