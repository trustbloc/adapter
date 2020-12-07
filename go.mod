// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter

go 1.15

require (
	github.com/PaesslerAG/gval v1.0.1
	github.com/PaesslerAG/jsonpath v0.1.1
	github.com/cenkalti/backoff/v4 v4.1.0 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201204175718-47143e0eada8
	github.com/mr-tron/base58 v1.1.3
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/ory/hydra-client-go v1.4.10
	github.com/piprate/json-gold v0.3.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5-0.20201203211818-a61e670a310e
	github.com/trustbloc/trustbloc-did-method v0.1.5-0.20201203214019-c56f43ad3f6e
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
)

replace (
	github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8
	github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e
)
