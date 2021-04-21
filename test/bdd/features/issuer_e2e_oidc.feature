#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@issuer_adapter
Feature: Issuer Adapter e2e with OIDC

#  Background: Setup External Agent
#    Given "WalletApp" agent is running on "localhost" port "9081" with webhook "http://localhost:9083" and controller "http://localhost:9082"

  @oidc_issuer_adapter_core
  Scenario Outline: Issuer adapter features
    Given Issuer Profile with id "<profileID>", name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>", requiresBlindedRoute "false", supportsAssuranceCred "<supportsAssuranceCred>" and oidc provider "https://issuer-hydra.trustbloc.local:9044/"
    And   Retrieved profile with id "<profileID>" contains name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>", requiresBlindedRoute "false", supportsAssuranceCred "<supportsAssuranceCred>" and oidc provider "https://issuer-hydra.trustbloc.local:9044/"
    Then  Issuer adapter shows the wallet connect UI when the issuer "<profileID>" wants to connect to the wallet
#    Then  Issuer adapter gets oidc authorization for the issuer "<profileID>" # wallet connect now automatically redirects to oidc auth
    And   Issuer adapter ("<profileID>") creates DIDComm connection invitation for "WalletApp"
    ## Mocking CHAPI flow here
    Then  "WalletApp" validates the supportedVCContexts "<supportedVCContexts>" in connect request from Issuer adapter ("<profileID>") along with primary credential type "<primaryVCType>" in case of supportsAssuranceCred "<supportsAssuranceCred>" and responds within "5" seconds
    And   Issuer adapter ("<profileID>") validates response from "WalletApp" and redirects to "<issuerURL>"
    When  "WalletApp" sends request credential message and receives credential from the issuer ("<profileID>")
    ## Mocking RP present proof call here (wallet calls instead of RP here)
    Then  "WalletApp" sends present proof request message to the the issuer ("<profileID>") and validates that the vc inside vp contains type "<authZFlowVCType>" along with supportsAssuranceCred "<supportsAssuranceCred>" validation
    Examples:
      | profileID           | profileName                           | issuerURL                                      | supportedVCContexts                                                                  | supportsAssuranceCred   | authZFlowVCType         | primaryVCType     |
      | prCardOIDC          | PRCard Issuer                         | http://mock-issuer.com:9080/prCard             | https://trustbloc.github.io/context/vc/examples/citizenship-v1.jsonld                | false                   | PermanentResidentCard   |                   |
      | creditCardOIDC      | CreditCard Issuer                     | http://mock-issuer.com:9080/creditCard         | https://trustbloc.github.io/context/vc/examples/credit-card-v1.jsonld                | false                   | CreditCardStatement     |                   |
      | driversLicenseOIDC  | Drivers License wth Evidence Issuer   | http://mock-issuer.com:9080/driversLicense     | https://trustbloc.github.io/context/vc/examples/driver-license-evidence-v1.jsonld    | true                    | DrivingLicenseEvidence  | mDL               |

  @oidc_issuer_adapter_routing
  Scenario Outline: Blinded Routing
    Given Issuer Profile with id "<profileID>", name "Blinded Routing", issuerURL "<issuerURL>", supportedVCContexts "https://w3id.org/citizenship/v3", requiresBlindedRoute "true", supportsAssuranceCred "<supportsAssuranceCred>" and oidc provider "https://issuer-hydra.trustbloc.local:9044/"
    And   Retrieved profile with id "<profileID>" contains name "Blinded Routing", issuerURL "<issuerURL>", supportedVCContexts "https://w3id.org/citizenship/v3", requiresBlindedRoute "true", supportsAssuranceCred "<supportsAssuranceCred>" and oidc provider "https://issuer-hydra.trustbloc.local:9044/"
    Then  Issuer adapter shows the wallet connect UI when the issuer "<profileID>" wants to connect to the wallet
#    Then  Issuer adapter gets oidc authorization for the issuer "<profileID>" # wallet connect now automatically redirects to oidc auth
    And   Issuer adapter ("<profileID>") creates DIDComm connection invitation for "WalletApp"
    Then  "WalletApp" with blinded routing support("http://localhost:9280") receives the DIDConnect request from Issuer adapter ("<profileID>")
    And   Issuer adapter ("<profileID>") validates response from "WalletApp" and redirects to "<issuerURL>"
    When  "WalletApp" sends request credential message and receives credential from the issuer ("<profileID>")
    Then  "WalletApp" sends present proof request message to the the issuer ("<profileID>") and validates that the vc inside vp contains type "PermanentResidentCard" along with supportsAssuranceCred "<supportsAssuranceCred>" validation
    Examples:
      | profileID                  | issuerURL                             | supportsAssuranceCred  |
      | profileBlindedRoutingOIDC  | http://mock-issuer.com:9080/prCard    | false                  |


  @oidc_issuer_adapter_wallet_bridge
  Scenario: Issuer connects to a remote wallet and sends store credential request
    # player: Issuer
    Given Issuer has a profile with name "PRCard Issuer 01", issuerURL "http://mock-issuer.com:9080/prCard", oidc provider "https://issuer-hydra.trustbloc.local:9044/" and supportedVCContexts "https://trustbloc.github.io/context/vc/examples/citizenship-v1.jsonld"
    And   issuer creates a deep link to invite remote wallet user "alice" to connect

    # player: alice
    Given Remote wallet "WalletApp" supports CHAPI request/response through DIDComm

    # player: Alice
    Then  "alice" loads remote wallet app "WalletApp" and accepts invitation

    # player: Issuer & Alice's wallet app
    When  Issuer checks wallet application profile for "alice" it finds profile status as "completed"
    And   issuer sends store credential request to remote wallet of "alice" and gets response back remote wallet app "WalletApp"

