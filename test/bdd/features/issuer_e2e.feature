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
    Then  Issuer adapter shows the wallet connect UI when the issuer "<profileID>" wants to connect to the wallet
    Examples:
      | profileID             | profileName           | profileCallBackURL                |
      | abc123                | Example Issuer        | http://example.com/cb             |
