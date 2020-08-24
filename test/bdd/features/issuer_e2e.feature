#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@issuer_adapter
Feature: Issuer Adapter e2e

  Scenario Outline: Issuer adapter features
    Given Issuer Profile with id "<profileID>", name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>" and supportsAssuranceCred "<supportsAssuranceCred>"
    And   Retrieved profile with id "<profileID>" contains name "<profileName>", issuerURL "<issuerURL>", supportedVCContexts "<supportedVCContexts>" and supportsAssuranceCred "<supportsAssuranceCred>"
    Given "Wallet" agent is running on "localhost" port "9081" with controller "http://localhost:9082"
    Then  Issuer adapter shows the wallet connect UI when the issuer "<profileID>" wants to connect to the wallet
    And   Issuer adapter ("<profileID>") creates DIDComm connection invitation for "Wallet"
    ## Mocking CHAPI flow here
    Then  "Wallet" validates the supportedVCContexts "<supportedVCContexts>" in connect request from Issuer adapter ("<profileID>") along with primary credential type "<primaryVCType>" in case of supportsAssuranceCred "<supportsAssuranceCred>" and responds within "5" seconds
    And   Issuer adapter ("<profileID>") validates response from "Wallet" and redirects to "<issuerURL>"
    When  "Wallet" sends request credential message and receives credential from the issuer ("<profileID>")
    ## Mocking RP present proof call here (wallet calls instead of RP here)
    Then  "Wallet" sends present proof request message to the the issuer ("<profileID>") and validates that the vc inside vp contains type "<authZFlowVCType>" along with supportsAssuranceCred "<supportsAssuranceCred>" validation
    Examples:
      | profileID       | profileName                           | issuerURL                                         | supportedVCContexts                                                                  | supportsAssuranceCred   | authZFlowVCType         | primaryVCType     |
      | prCard          | PRCard Issuer                         | http://issuer.example.com:9080/prCard             | https://w3id.org/citizenship/v3                                                      | false                   | PermanentResidentCard   |                   |
      | creditCard      | CreditCard Issuer                     | http://issuer.example.com:9080/creditCard         | https://trustbloc.github.io/context/vc/examples/credit-card-v1.jsonld                | false                   | CreditCardStatement     |                   |
      | driversLicense  | Drivers License wth Evidence Issuer   | http://issuer.example.com:9080/driversLicense     | https://trustbloc.github.io/context/vc/examples/driver-license-evidence-v1.jsonld    | true                    | DrivingLicenseEvidence  | mDL               |
