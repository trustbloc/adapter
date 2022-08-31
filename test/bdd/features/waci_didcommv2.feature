#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@waci_didcommv2
Feature: WACI DIDComm V2

  @issuer_adapter_waci_v2
  Scenario Outline: Issuer adapter features
    Given "<walletID>" agent is running on "localhost" port "9081" with webhook "http://localhost:9083" and controller "http://localhost:9082"
    And Wallet "<walletID>" has profile created and unlocked
    #This scenario only has output descriptors configured in manifest-config file.
    Given Issuer Profile with id "<profileID>", name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>", scopes "<scopes>", issuer id "<issuerID>", linked wallet "<linkedWallet>" and oidc provider "https://issuer-hydra.trustbloc.local:9044/" with DIDComm V2 and WACI support
    And   Retrieved profile with id "<profileID>" contains name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>", scopes "<scopes>", issuer id "<issuerID>", linked wallet "<linkedWallet>" and oidc provider "https://issuer-hydra.trustbloc.local:9044/" with DIDComm V2 and WACI support
    Then  Issuer adapter shows the wallet connect UI when the issuer "<profileID>" with scopes "<scopes>" wants to connect to the wallet
    And   Issuer adapter ("<profileID>") creates DIDComm connection invitation for "<walletID>"
    # While performing WACI interaction, validation of offer credential attachment(manifest and response) and
    # request credential with credential application attachment presentation is sent via universal wallet
    And   "<walletID>" accepts invitation from issuer adapter "<profileID>" and performs WACI credential issuance interaction with manifest with PEx requirement "false"
    And   "<walletID>" received web redirect info from "<profileID>" after successful completion of WACI credential issuance interaction
    Examples:
      | profileID  | profileName   | issuerURL                          | supportedVCContexts                                                   | scopes     | issuerID                         | linkedWallet                    | walletID  |
      | prCardWACI | PRCard Issuer | http://mock-issuer.com:9080/prCard | https://trustbloc.github.io/context/vc/examples/citizenship-v1.jsonld | prc        | did:example:123?linked-domains=3 | https://example.wallet.com/waci | WalletApp |

  @issuer_adapter_waci_v2_withPEx
  Scenario Outline: Issuer adapter features
    Given "<walletID>" agent is running on "localhost" port "9081" with webhook "http://localhost:9083" and controller "http://localhost:9082"
    And Wallet "<walletID>" has profile created and unlocked
    #This scenario has output descriptors and prc card input descriptor configured in manifest-config file.
    Given Issuer Profile with id "<profileID>", name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>", scopes "<scopes>", issuer id "<issuerID>", linked wallet "<linkedWallet>" and oidc provider "https://issuer-hydra.trustbloc.local:9044/" with DIDComm V2 and WACI support
    And   Retrieved profile with id "<profileID>" contains name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>", scopes "<scopes>", issuer id "<issuerID>", linked wallet "<linkedWallet>" and oidc provider "https://issuer-hydra.trustbloc.local:9044/" with DIDComm V2 and WACI support
    Then  Issuer adapter shows the wallet connect UI when the issuer "<profileID>" with scopes "<scopes>" wants to connect to the wallet
    And   Issuer adapter ("<profileID>") creates DIDComm connection invitation for "<walletID>"
    And   "<walletID>" accepts invitation from issuer adapter "<profileID>" and performs WACI credential issuance interaction with manifest with PEx requirement "true"
    And   "<walletID>" received web redirect info from "<profileID>" after successful completion of WACI credential issuance interaction
    Examples:
      | profileID  | profileName            | issuerURL                                  | supportedVCContexts                                                               | scopes     | issuerID                         | linkedWallet                    | walletID  |
      | mDLWACI    | Driving License Issuer | http://mock-issuer.com:9080/driversLicense | https://trustbloc.github.io/context/vc/examples/driver-license-evidence-v1.jsonld | mDL        | did:example:123?linked-domains=3 | https://example.wallet.com/waci | WalletMDLApp |

  @verifier_adapter_waci_v2
  Scenario: WACI flow between Verifier and Wallet using DIDComm V2
    Given the "Mock Wallet" is running on "localhost" port "9081" with webhook "http://localhost:9083" and controller "http://localhost:9082"
    And the "Mock Issuer Adapter" is running on "localhost" port "10010" with controller "http://localhost:10011"

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
