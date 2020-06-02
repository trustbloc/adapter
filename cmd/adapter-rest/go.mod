// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edge-adapter/cmd/adapter-rest

go 1.14

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/go-sql-driver/mysql v1.5.0
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.7.4
	github.com/ory/hydra-client-go v1.4.10
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/rs/cors v1.7.0
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.5.1
	github.com/trustbloc/edge-adapter v0.0.0-00010101000000-000000000000
	github.com/xo/dburl v0.0.0-20200124232849-e9ec94f52bc3
	github.com/trustbloc/edge-core v0.1.4-0.20200520210037-e95d2dd69134
)

replace github.com/trustbloc/edge-adapter => ../..
