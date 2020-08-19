#!/usr/bin/env bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

echo `pwd`

../../.build/did-method-cli/cli create-config --sidetree-url https://localhost:48326/sidetree/0.0.1 --tls-cacerts ./fixtures/keys/tls/ec-cacert.pem --sidetree-write-token rw_token --config-file ./fixtures/did-trustbloc/config-data/config.json --output-directory ./fixtures/did-trustbloc/config
rm -rf ./fixtures/did-trustbloc/config/stakeholder-one.trustbloc.local
mv ./fixtures/did-trustbloc/config/stakeholder-one.trustbloc.local:8088 ./fixtures/did-trustbloc/config/stakeholder-one.trustbloc.local
