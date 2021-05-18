// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter

go 1.16

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210517160459-a72f856f36b8
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210517231016-de60084e8513
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210413155718-eeb5b3c708be
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210429205242-c5e97865879c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210422133815-2ef2d99cb692
	github.com/ory/hydra-client-go v1.4.10
	github.com/piprate/json-gold v0.4.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210331113925-b13dedfe75eb
	golang.org/x/oauth2 v0.0.0-20200902213428-5d25da1a8d43
	gopkg.in/square/go-jose.v2 v2.5.1
)
