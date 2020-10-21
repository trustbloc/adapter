#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@issuer_adapter
Feature: Issuer Adapter e2e

  Background: Setup External Agent
    Given "Wallet" agent is running on "localhost" port "9081" with webhook "http://localhost:9083" and controller "http://localhost:9082"

  @issuer_adapter_healthcheck
  Scenario: Issuer adapter healthcheck
    When an HTTP GET is sent to "https://localhost:9070/healthcheck"
    Then the JSON path "status" of the response equals "success"

  @issuer_adapter_core
  Scenario Outline: Issuer adapter features
    Given Issuer Profile with id "<profileID>", name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>" and supportsAssuranceCred "<supportsAssuranceCred>"
    And   Retrieved profile with id "<profileID>" contains name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>" and supportsAssuranceCred "<supportsAssuranceCred>"
    Then  Issuer adapter shows the wallet connect UI when the issuer "<profileID>" wants to connect to the wallet
    And   Issuer adapter ("<profileID>") creates DIDComm connection invitation for "Wallet"
    ## Mocking CHAPI flow here
    Then  "Wallet" validates the supportedVCContexts "<supportedVCContexts>" in connect request from Issuer adapter ("<profileID>") along with primary credential type "<primaryVCType>" in case of supportsAssuranceCred "<supportsAssuranceCred>" and responds within "5" seconds
    And   Issuer adapter ("<profileID>") validates response from "Wallet" and redirects to "<issuerURL>"
    When  "Wallet" sends request credential message and receives credential from the issuer ("<profileID>")
    ## Mocking RP present proof call here (wallet calls instead of RP here)
    Then  "Wallet" sends present proof request message to the the issuer ("<profileID>") and validates that the vc inside vp contains type "<authZFlowVCType>" along with supportsAssuranceCred "<supportsAssuranceCred>" validation
    Examples:
      | profileID       | profileName                           | issuerURL                                      | supportedVCContexts                                                                  | supportsAssuranceCred   | authZFlowVCType         | primaryVCType     |
      | prCard          | PRCard Issuer                         | http://mock-issuer.com:9080/prCard             | https://w3id.org/citizenship/v3                                                      | false                   | PermanentResidentCard   |                   |
      | creditCard      | CreditCard Issuer                     | http://mock-issuer.com:9080/creditCard         | https://trustbloc.github.io/context/vc/examples/credit-card-v1.jsonld                | false                   | CreditCardStatement     |                   |
      | driversLicense  | Drivers License wth Evidence Issuer   | http://mock-issuer.com:9080/driversLicense     | https://trustbloc.github.io/context/vc/examples/driver-license-evidence-v1.jsonld    | true                    | DrivingLicenseEvidence  | mDL               |

  @issuer_adapter_routing
  Scenario: Blinded Routing
    Given Issuer Profile with id "profileBlindedRouting", name "Blinded Routing", issuerURL "http://mock-issuer.com:9080/prCard", supportedVCContexts "https://w3id.org/citizenship/v3 " and supportsAssuranceCred "false"
    And   Retrieved profile with id "profileBlindedRouting" contains name "Blinded Routing", issuerURL "http://mock-issuer.com:9080/prCard", supportedVCContexts "https://w3id.org/citizenship/v3" and supportsAssuranceCred "false"
    Then  Issuer adapter shows the wallet connect UI when the issuer "profileBlindedRouting" wants to connect to the wallet
    And   Issuer adapter ("profileBlindedRouting") creates DIDComm connection invitation for "Wallet"
    Then  "Wallet" with blinded routing support("http://localhost:9280") receives the DIDConnect request from Issuer adapter ("profileBlindedRouting")
