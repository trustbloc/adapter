#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@rp_adapter
Feature: RP Adapter
  Background: Setup External Agent
    Given the "Mock Wallet" is running on "localhost" port "9081" with controller "http://localhost:9082"
    And the "Mock Issuer Adapter" is running on "localhost" port "10010" with controller "http://localhost:10011"

  Scenario: Register relying party
    When a request is sent to create an RP tenant with label "test-tenant" and callback "http://todo.com"
    Then the trustbloc DID of the tenant with label "test-tenant" is resolvable
    And the client ID of the tenant with label "test-tenant" is registered at hydra

  Scenario: did-exchange with the web wallet
    Given a registered rp tenant with label "didexchange" and callback "http://rp.example.com/callback"
    When the rp tenant "didexchange" redirects the user to the rp adapter
    And the rp adapter "didexchange" submits a CHAPI request to "Mock Wallet" with presentation-definitions and a didcomm invitation to connect
    And "Mock Wallet" accepts the didcomm invitation
    Then "Mock Wallet" connects with the RP adapter "didexchange"
