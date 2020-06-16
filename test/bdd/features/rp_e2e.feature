#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@rp_adapter
Feature: RP Adapter
  Scenario: Register relying party
    When a request is sent to create an RP tenant with label "test-tenant"
    Then the trustbloc DID of the tenant with label "test-tenant" is resolvable
    And the client ID of the tenant with label "test-tenant" is registered at hydra
