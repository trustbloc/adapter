#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@rp_adapter
Feature: RP Adapter
  Background: Setup External Agent
    Given the "Mock Wallet" is running on "localhost" port "9081" with webhook "http://localhost:9083" and controller "http://localhost:9082"
    And the "Mock Issuer Adapter" is running on "localhost" port "10010" with controller "http://localhost:10011"

  @rp_adapter_healthcheck
  Scenario: RP adapter healthcheck
    When an HTTP GET is sent to "https://localhost:8070/healthcheck"
    Then the JSON path "status" of the response equals "success"

  Scenario: Register relying party
    When a request is sent to create an RP tenant with label "test-tenant" and scopes "credit_card_stmt:remote"
    Then the trustbloc DID of the tenant with label "test-tenant" is resolvable
    And the client ID of the tenant with label "test-tenant" and scopes "credit_card_stmt:remote" is registered at hydra

  @rp_wallet_didex
  Scenario: Establishment of didcomm connection with the web wallet
    Given a registered rp tenant with label "didcommconnection" and scopes "credit_card_stmt:remote"
    When the rp tenant "didcommconnection" redirects the user to the rp adapter with scope "credit_card_stmt:remote"
    And the rp adapter "didcommconnection" submits a CHAPI request to "Mock Wallet" with presentation-definitions and a didcomm invitation to connect
    And "Mock Wallet" accepts the didcomm invitation from "didcommconnection"
    Then "Mock Wallet" connects with the RP adapter "didcommconnection"

  @rp_adapter_cred
  Scenario: Returns both local and remote user data to the relying party with the user's consent
    Given "Mock Issuer Adapter" and "Mock Wallet" have a didcomm connection
    And an rp tenant with label "userdata" and scopes "credit_card_stmt:remote,driver_license:local" that requests the "credit_card_stmt:remote,driver_license:local" scope from the "Mock Wallet" with blinded routing "false"
    And the "Mock Wallet" provides an authorization credential via CHAPI that contains the DIDs of rp "userdata" and issuer "Mock Issuer Adapter"
    When "Mock Issuer Adapter" responds to "userdata" with the user's data
    Then the user is redirected to the rp tenant "userdata"
    And the rp tenant "userdata" retrieves the user data from the rp adapter

  @rp_adapter_blinded_cred
  Scenario: Returns both local and remote user data to the relying party with the user's consent with Blinded RP
    Given "Mock Issuer Adapter" and "Mock Wallet" have a didcomm connection
    And an rp tenant with label "blinded_userdata" and scopes "credit_card_stmt:remote,driver_license:local" that requests the "credit_card_stmt:remote,driver_license:local" scope from the "Mock Wallet" with blinded routing "true"
    And the "Mock Wallet" provides an authorization credential via CHAPI that contains the DIDs of blinded rp "blinded_userdata" registered with router "http://localhost:9280" and issuer "Mock Issuer Adapter"
    When "Mock Issuer Adapter" responds to "blinded_userdata" with the user's data
    Then the user is redirected to the rp tenant "blinded_userdata"
    And the rp tenant "blinded_userdata" retrieves the user data from the rp adapter
