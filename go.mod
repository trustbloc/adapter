// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter

go 1.15

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210324213044-074644c18933
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210306194409-6e4c5d622fbc
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210325134531-84a30b2ecacb
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210320144851-40976de98ccf
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210320144851-40976de98ccf
	github.com/ory/hydra-client-go v1.4.10
	github.com/piprate/json-gold v0.4.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210310142750-7eb11997c4a9
	golang.org/x/oauth2 v0.0.0-20200902213428-5d25da1a8d43
	gopkg.in/square/go-jose.v2 v2.5.1
)
