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
    And Wallet "WalletApp" has profile created and unlocked

  @issuer_adapter_waci
  Scenario Outline: Issuer adapter features
    Given Issuer Profile with id "<profileID>", name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>", linked wallet "<linkedWallet>" and oidc provider "https://issuer-hydra.trustbloc.local:9044/" with WACI support
    And   Retrieved profile with id "<profileID>" contains name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>", linked wallet "<linkedWallet>" and oidc provider "https://issuer-hydra.trustbloc.local:9044/" with WACI support
    Then  Issuer adapter shows the wallet connect UI when the issuer "<profileID>" wants to connect to the wallet
    And   Issuer adapter ("<profileID>") creates DIDComm connection invitation for "<walletID>"
    And   "<walletID>" accepts invitation from issuer adapter "<profileID>" and performs WACI credential issuance interaction
    And   "<walletID>" received web redirect info from "<profileID>" after successful completion of WACI credential issuance interaction
    Examples:
      | profileID  | profileName   | issuerURL                          | supportedVCContexts                                                   | linkedWallet                    | walletID  |
      | prCardWACI | PRCard Issuer | http://mock-issuer.com:9080/prCard | https://trustbloc.github.io/context/vc/examples/citizenship-v1.jsonld | https://example.wallet.com/waci | WalletApp |

