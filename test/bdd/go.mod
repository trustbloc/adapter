// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter/test/bdd

go 1.16

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210819214613-1554e98c6f85
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210816155124-45ab1ecd4762
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210807121559-b41545a4f1e8
	github.com/ory/hydra-client-go v1.4.10
	github.com/piprate/json-gold v0.4.1-0.20210813112359-33b90c4ca86c
	github.com/sirupsen/logrus v1.7.0
	github.com/tidwall/gjson v1.6.7
	github.com/trustbloc/edge-adapter v0.0.0
	github.com/trustbloc/edge-core v0.1.7-0.20210816120552-ed93662ac716
	github.com/trustbloc/hub-router v0.1.7-0.20210528152128-8f8587548e65
	golang.org/x/oauth2 v0.0.0-20210427180440-81ed05c6b58c
	gotest.tools/v3 v3.0.3 // indirect
)

replace (
	github.com/trustbloc/edge-adapter => ../..
	// https://github.com/ory/dockertest/issues/208#issuecomment-686820414
	golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
)
