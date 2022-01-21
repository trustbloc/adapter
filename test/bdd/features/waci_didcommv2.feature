#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@waci_didcommv2
Feature: WACI DIDComm V2

  Background: Setup External Agent
    Given the "Mock Wallet" is running on "localhost" port "9081" with webhook "http://localhost:9083" and controller "http://localhost:9082"
    And the "Mock Issuer Adapter" is running on "localhost" port "10010" with controller "http://localhost:10011"

  Scenario: WACI flow between Verifier and Wallet using DIDComm V2
    Given a registered rp tenant with label "waci_demo" and scopes "driver_license:local" and linked wallet "https://example.wallet.com/waci" with WACI support using DIDComm V2
    When the rp tenant "waci_demo" redirects the user to the rp adapter with scope "driver_license:local"
    And the rp adapter "waci_demo" submits a CHAPI request to "Mock Wallet" with out-of-band invitation
    # TODO remove connections once AFG supports DIDComm v2
    And "Mock Wallet" accepts the didcomm v2 invitation from "waci_demo"
    Then "Mock Wallet" connects with the RP adapter "waci_demo"
    Then "Mock Wallet" submits the presentation to the RP adapter "waci_demo"
    Then "Mock Wallet" receives acknowledgement from "waci_demo" containing redirect with status "OK"
    Then the user is redirected to the rp tenant "waci_demo"
    Then the rp tenant "waci_demo" retrieves the user data from the rp adapter
