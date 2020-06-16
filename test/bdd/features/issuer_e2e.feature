#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@issuer_adapter
Feature: Issuer Adapter e2e

  Scenario Outline: Issuer adapter features
    Given Issuer Profile with id "<profileID>", name "<profileName>" and callbackURL "<profileCallBackURL>"
    And   Retrieved profile with id "<profileID>" contains name "<profileName>" and callbackURL "<profileCallBackURL>"
    Given "Wallet" agent is running
    Then  Issuer adapter shows the wallet connect UI when the issuer "<profileID>" wants to connect to the wallet
    And   Issuer adapter ("<profileID>") creates DIDExchange request for "Wallet"
    ## Mocking CHAPI flow here
    Then  "Wallet" responds to connect request from Issuer adapter ("<profileID>")
    And   Issuer adapter ("<profileID>") validates response from "Wallet"
    Examples:
      | profileID             | profileName           | profileCallBackURL                |
      | abc123                | Example Issuer        | http://example.com/cb             |
