#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@issuer_adapter
Feature: Issuer Adapter e2e with WACI

  Background: Setup External Agent
    Given "WalletApp" agent is running on "localhost" port "9081" with webhook "http://localhost:9083" and controller "http://localhost:9082"

  @issuer_adapter_waci
  Scenario Outline: Issuer adapter features
    Given Issuer Profile with id "<profileID>", name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>" and oidc provider "https://issuer-hydra.trustbloc.local:9044/" with WACI support
    And   Retrieved profile with id "<profileID>" contains name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>" and oidc provider "https://issuer-hydra.trustbloc.local:9044/" with WACI support
    # TODO https://github.com/trustbloc/adapter/issues/545 add waci bdd tests
    Examples:
      | profileID  | profileName   | issuerURL                          | supportedVCContexts                                                   |
      | prCardWACI | PRCard Issuer | http://mock-issuer.com:9080/prCard | https://trustbloc.github.io/context/vc/examples/citizenship-v1.jsonld |

