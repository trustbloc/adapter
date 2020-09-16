// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter/test/bdd

go 1.14

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/google/uuid v1.1.1
	github.com/hyperledger/aries-framework-go v0.1.5-0.20200904153313-0e08dc3311d4
	github.com/ory/hydra-client-go v1.4.10
	github.com/piprate/json-gold v0.3.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.6.0
	github.com/tidwall/gjson v1.6.0
	github.com/trustbloc/edge-adapter v0.0.0
	github.com/trustbloc/edge-core v0.1.5-0.20200916124536-c32454a16108
	github.com/trustbloc/trustbloc-did-method v0.1.4
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
)

replace github.com/trustbloc/edge-adapter => ../..
