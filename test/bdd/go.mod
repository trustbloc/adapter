// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter/test/bdd

go 1.16

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.7.4
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.8-0.20211203093644-b7d189cc06f4
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.1.3
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20211026175505-52f559aeeb86
	github.com/ory/hydra-client-go v1.4.10
	github.com/piprate/json-gold v0.4.1-0.20210813112359-33b90c4ca86c
	github.com/sirupsen/logrus v1.8.1
	github.com/tidwall/gjson v1.6.7
	github.com/trustbloc/edge-adapter v0.0.0
	github.com/trustbloc/edge-core v0.1.7
	github.com/trustbloc/hub-router v0.1.7-0.20210916163414-5ed617fc6113
	golang.org/x/oauth2 v0.0.0-20210427180440-81ed05c6b58c
)

replace github.com/trustbloc/edge-adapter => ../..
