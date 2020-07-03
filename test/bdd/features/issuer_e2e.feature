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
    Given "Wallet" agent is running on "localhost" port "9081" with controller "http://localhost:9082"
    Then  Issuer adapter shows the wallet connect UI when the issuer "<profileID>" wants to connect to the wallet
    And   Issuer adapter ("<profileID>") creates DIDExchange request for "Wallet"
    ## Mocking CHAPI flow here
    Then  "Wallet" responds to connect request from Issuer adapter ("<profileID>") within "5" seconds
    And   Issuer adapter ("<profileID>") validates response from "Wallet" and redirects to "<profileCallBackURL>"
    When  "Wallet" sends request credential message and receives credential from the issuer ("<profileID>")
    ## Mocking RP present proof call here (wallet calls instead of RP here)
    Then  "Wallet" sends present proof request message and receives presentation from the issuer ("<profileID>")
    Examples:
      | profileID             | profileName           | profileCallBackURL                |
      | abc123                | Example Issuer        | http://example.com/cb             |
