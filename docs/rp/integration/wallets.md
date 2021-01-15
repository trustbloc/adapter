# Integration Guide for Wallets

## Purpose of this document

This document serves as a guide for integrating end-user
[wallets](https://github.com/hyperledger/aries-rfcs/blob/master/concepts/0004-agents/README.md) to the RP Adapter.


## Overview

The End User's web browser is redirected to the RP Adapter by the Relying Party. The Adapter then 
requests [web credentials](https://w3c-ccg.github.io/credential-handler-api/) from the User's Agent. The request is
in the form of a
[Presentation Definition](https://identity.foundation/presentation-exchange/#presentation-definition). A
[DIDComm connection](https://github.com/hyperledger/aries-rfcs/blob/master/concepts/0005-didcomm/README.md) is also
bootstrapped via an
[Out-of-Band invitation](https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md).

The Adapter may request verifiable credentials with statements about a subject, or it may request
[Authorization Credentials](https://github.com/trustbloc/context/blob/main/vc/authorization-credential-v1.jsonld) that
the RP Adapter can then use to fetch the "normal" credentials.

> **TODO** document authorization credentials

In all cases, once the RP Adapter has collected all credentials and verified requirements are met as per the
original presentation definition, the End User's web browser will be redirected back to the Relying Party's origin.

![overview](http://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/trustbloc/edge-adapter/main/docs/rp/integration/wallet_rpadapter_int_overview.puml)


## Requirements

The Wallet needs to support the following specifications listed below. Wallet implementors are encouraged to use the
high-level [TrustBloc Agent SDK](https://github.com/trustbloc/agent-sdk) APIs that encapsulate some of the complexity.

> **TODO** update Agent SDK link once the SDK docs are available

* [Credential Handler API 1.0](https://w3c-ccg.github.io/credential-handler-api/).
  * This [polyfill](https://github.com/digitalbazaar/web-credential-handler) can be used to register a Service Worker and
    receive credential events.
* Decentralized Identity Foundation's [Presentation-Exchange](https://identity.foundation/presentation-exchange/) format.
* Produce and consume [Decentralized Identifiers](https://w3c.github.io/did-core/) in JSON-LD format.
  * Supported DID methods are:
    * [`did:trustbloc`](https://github.com/trustbloc/trustbloc-did-method/blob/main/docs/spec/trustbloc-did-method.md).
    * [`did:peer`](https://identity.foundation/peer-did-method-spec/).
* Produce and consume [Verifiable Credentials & Presentations](https://www.w3.org/TR/vc-data-model/) in JSON-LD format.
* Produce Verifiable Credentials of type
    [`AuthorizationCredential`](https://github.com/trustbloc/context/blob/main/vc/authorization-credential-v1.jsonld)
    to enable OAuth-like use cases.
* [Aries RFC0434 Out-of-Band Protocol](https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md).
* [Aries RFC0023 DID Exchange Protocol](https://github.com/hyperledger/aries-rfcs/blob/master/features/0023-did-exchange/README.md).


## Credential Requests

The RP Adapter sends a web credentials request to the web browser with the following general form:

```jsonc
{
    "web": {
        "VerifiablePresentation": {
            "query": [
                {
                    "type": "PresentationDefinitionQuery",
                    "presentationDefinitionQuery": {
                        // presentation definitions object
                    }
                },
                {
                    "type": "DIDConnect",
                    "invitation": {
                        // Aries Out-of-Band DIDComm invitation
                    },
                    "credentials": [
                        // List of Verifiable Credentials accrediting the relying party - as identified by their public
                        // DID - as a participant in a governance framework.
                    ]
                }
            ]
        }
    }
}
```

<details><summary>Full example</summary>

```json
{
    "web": {
        "VerifiablePresentation": {
            "query": [
                {
                    "type": "PresentationDefinitionQuery",
                    "presentationDefinitionQuery": {
                        "input_descriptors": [
                            {
                                "id": "driver_license:local",
                                "schema": {
                                    "uri": [
                                        "https://trustbloc.github.io/context/vc/examples/mdl-v1.jsonld"
                                    ],  
                                    "name": "Driver's license.",
                                    "purpose": "Verify your identity."
                                }   
                            },  
                            {
                                "id": "credit_score:remote",
                                "schema": {
                                    "uri": [
                                        "https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld"
                                    ],  
                                    "name": "Authorization to access your credit score.",
                                    "purpose": "Determine eligibility for the service."
                                },  
                                "constraints": {
                                    "fields": [
                                        {
                                            "path": [
                                                "$.credentialSubject.scope[*].schema.uri"
                                            ],  
                                            "filter": {
                                                "const": "https://trustbloc.github.io/context/vc/examples/credit-score-v1.jsonld"
                                            }
                                        }
                                    ]
                                }
                            },
                            {
                                "id": "driver_license_evidence:remote",
                                "schema": {
                                    "uri": [
                                        "https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld"
                                    ],
                                    "name": "Authorization to verify your driver's license.",
                                    "purpose": "We need your consent to verify issuance of your driver's license."
                                },
                                "constraints": {
                                    "fields": [
                                        {
                                            "path": [
                                                "$.credentialSubject.scope[*].schema.uri"
                                            ],
                                            "filter": {
                                                "const": "https://trustbloc.github.io/context/vc/examples/driver-license-evidence-v1.jsonld"
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                },
                {
                    "type": "DIDConnect",
                    "invitation": {
                        "@id": "71710bb8-e703-4427-8f72-8b18c7aa38a2",
                        "@type": "https://didcomm.org/oob-invitation/1.0/invitation",
                        "label": "Demo Relying Party",
                        "service": [
                            "did:trustbloc:discovery.trustbloc.example.com:EiDBGODe_WiLwDOxMp_7CI6NKOjk4KbtwqUv0d04EFRiyg"
                        ],
                        "protocols": [
                            "https://didcomm.org/didexchange/1.0"
                        ]
                    },
                    "credentials": [
                        {
                            "@context": [
                                "https://www.w3.org/2018/credentials/v1",
                                "https://trustbloc.github.io/context/governance/context.jsonld",
                                "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
                            ],
                            "credentialStatus": {
                                "id": "https://governance.trustbloc.example.com/governance/status/1",
                                "type": "CredentialStatusList2017"
                            },
                            "credentialSubject": {
                                "data_uri": "https://example.com/data.json",
                                "define": [
                                    {
                                        "id": "did:trustbloc:discovery.trustbloc.example.com:EiDBGODe_WiLwDOxMp_7CI6NKOjk4KbtwqUv0d04EFRiyg",
                                        "name": "DID"
                                    }
                                ],
                                "description": "Sample governance framework for the TrustBloc sandbox.",
                                "docs_uri": "https://example.com/docs",
                                "duties": [
                                    {
                                        "name": "safe-accredit",
                                        "uri": "https://example.com/responsible-accredit"
                                    }
                                ],
                                "geos": [
                                    "Canadian"
                                ],
                                "jurisdictions": [
                                    "ca"
                                ],
                                "logo": "https://example.com/logo",
                                "name": "TrustBloc Sandbox",
                                "privileges": [
                                    {
                                        "name": "accredit",
                                        "uri": "https://example.com/accredit"
                                    }
                                ],
                                "roles": [
                                    "accreditor"
                                ],
                                "topics": [
                                    "banking"
                                ],
                                "version": "1.0"
                            },
                            "issuer": "did:trustbloc:discovery.trustbloc.example.com:EiC36Qo-8fNl6avOSpC7hEjH8PPLQRpzdEZZKmYjDvYxnQ",
                            "proof": {
                                "created": "2020-09-16T21:58:19.066334758Z",
                                "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..8peyFO372PGqAX4e1OfNEI9Mo5BPwX-HQtkSH2aPHXIHZ_sqWE6byMkd5UiP7CJWNPw6Do5XhFvgUfLNLDGvAQ",
                                "proofPurpose": "assertionMethod",
                                "type": "Ed25519Signature2018",
                                "verificationMethod": "did:trustbloc:discovery.trustbloc.example.com:EiC36Qo-8fNl6avOSpC7hEjH8PPLQRpzdEZZKmYjDvYxnQ#YYgJrTHZt6p1czNEBoKY23cvgg_Z0tuY42W1yXs3yvI"
                            },
                            "type": [
                                "VerifiableCredential",
                                "GovernanceCredential"
                            ]
                        }
                    ]
                }
            ]
        }
    }
}
```
</details>

> **TODO** rationalize use of two query types. Note: there is no response received currently for DIDConnect

### Query Type 'PresentationDefinitionQuery'

The [Presentation Definition](https://identity.foundation/presentation-exchange/#presentation-definition) may include
descriptors for [`AuthorizationCredentials`](https://github.com/trustbloc/context/blob/main/vc/authorization-credential-v1.jsonld).
When they do they come in the form of:

```jsonc
{
    "schema": {
        "uri": ["https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld"],
        "name": "some name",
        "purpose": "some purpose"
    },
    "constraints": {
        "fields": [
            {
                "path": ["$.credentialSubject.scope[*].schema.uri"],
                "filter": {
                    "const": "https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld"
                }
            }
        ]
    }
}
```

This request is asking for a credential defined in JSON-LD vocabulary
`https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld` with the `schema.uri` inside its
`credentialSubject.scope` set to `https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld`. In plain words, this
descriptor is requesting an `AuthorizationCredential` to use for obtaining credentials of the types defined in
`https://trustbloc.github.io/context/vc/examples-ext-v1.jsonld`.

Here is an example `AuthorizationCredential` that fulfills this requirement:

> **TODO** this example is missing the `scope` element

<details><summary>Example</summary>

```json
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld"
    ],
    "type": [
        "VerifiableCredential",
        "AuthorizationCredential"
    ],
    "id": "urn:uuid:6c715251-d0bc-44cd-be39-c57c237f382f",
    "issuanceDate": "2020-10-26T22:34:25.693548266Z",
    "issuer": "urn:uuid:5fe5367d-b608-4ae0-9c96-f7b521cf5a3a",
    "credentialSubject": {
        "id": "urn:uuid:9017cd03-3d50-4554-9eaf-354f87b3f70e",
        "issuerDIDDoc": {
            "doc": {
                "@context": [
                    "https://w3id.org/did/v1"
                ],
                "assertionMethod": [
                    "#QS1JDThR8iFru8OVt1_ESQ3vACH9vWpqCUjk3Jgyvgc"
                ],
                "authentication": [
                    "#QS1JDThR8iFru8OVt1_ESQ3vACH9vWpqCUjk3Jgyvgc"
                ],
                "created": "2020-10-26T22:34:25.662914267Z",
                "id": "did:peer:1zQmeFUNUg2hu6tQ7U4vUk4AWenqGZGr3wBCSVfXtcjk67xK",
                "publicKey": [
                    {
                        "controller": "#id",
                        "id": "#QS1JDThR8iFru8OVt1_ESQ3vACH9vWpqCUjk3Jgyvgc",
                        "publicKeyBase58": "2RzhQXGzr4Q8sbEFU1jXRhJLqYr9bvpA5cuot1DTFcT8",
                        "type": "Ed25519VerificationKey2018"
                    }
                ],
                "service": [
                    {
                        "id": "#agent",
                        "priority": 0,
                        "recipientKeys": [
                            "2RzhQXGzr4Q8sbEFU1jXRhJLqYr9bvpA5cuot1DTFcT8"
                        ],
                        "serviceEndpoint": "https://issuer-adapter-didcomm.trustbloc.example.com",
                        "type": "did-communication"
                    }
                ],
                "updated": "2020-10-26T22:34:25.662914267Z"
            },
            "id": "did:peer:1zQmeFUNUg2hu6tQ7U4vUk4AWenqGZGr3wBCSVfXtcjk67xK"
        },
        "requestingPartyDIDDoc": {
            "doc": {
                "@context": [
                    "https://w3id.org/did/v1"
                ],
                "assertionMethod": [
                    "#98oGE-VuEqt3lMibQKulB4OJzhRHgzOrao8U_Y16sJA"
                ],
                "authentication": [
                    "#98oGE-VuEqt3lMibQKulB4OJzhRHgzOrao8U_Y16sJA"
                ],
                "created": "2020-10-26T22:34:24.651560358Z",
                "id": "did:peer:1zQmTR4Yxqix6cKGx14f21A35XfRc9RDqzpwSoBQxmC13Rio",
                "publicKey": [
                    {
                        "controller": "#id",
                        "id": "#98oGE-VuEqt3lMibQKulB4OJzhRHgzOrao8U_Y16sJA",
                        "publicKeyBase58": "FmiK1AGLSDYQhxyiJ6zo59VoBBhaU5uCF8ksoGBMCo8M",
                        "type": "Ed25519VerificationKey2018"
                    }
                ],
                "service": [
                    {
                        "id": "#agent",
                        "priority": 0,
                        "recipientKeys": [
                            "FmiK1AGLSDYQhxyiJ6zo59VoBBhaU5uCF8ksoGBMCo8M"
                        ],
                        "serviceEndpoint": "https://verifier-adapter-didcomm.trustbloc.example.com",
                        "type": "did-communication"
                    }
                ],
                "updated": "2020-10-26T22:34:24.651560358Z"
            },
            "id": "did:peer:1zQmTR4Yxqix6cKGx14f21A35XfRc9RDqzpwSoBQxmC13Rio"
        },
        "subjectDID": "did:peer:1zQme2FTBHheMdfX9CQmX3UjGkUpmLtmP1T3Jbu3Qu8MnW2P"
    },
    "proof": {
        "created": "2020-10-26T22:34:26.102106902Z",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..1XTTXFb66rS1tGGHPkAurLQe5_WO81G66YUbbxjYSuK10-JfkZrRyOCEgCMnkgb2QZibgwa_gb3kx4LvwjtTAA",
        "proofPurpose": "assertionMethod",
        "type": "Ed25519Signature2018",
        "verificationMethod": "did:trustbloc:discovery.trustbloc.example.com:EiDhbJFybWBLwZCP58A-dgQRRHXyCIfHA_Au9_AShgUQJw#CoG7IaHn5I4Ji0AcmRFS7Ltzf66YvrKnWwqGcSPkLgY"
    }
}
```
</details>

### Query Type 'DIDConnect'

The DIDComm connection invitation is in the format of an
[Aries RFC0434 Out-of-Band Invitation](https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md#invitation-httpsdidcommorgout-of-bandverinvitation).
The `service` entry has a
[`did:trustbloc` DID](https://github.com/trustbloc/trustbloc-did-method/blob/main/docs/spec/trustbloc-did-method.md).
The `trustbloc` DID is the public identifier for the relying party. It possesses a `service` entry following the
[Aries RFC0067 DIDComm Service Conventions](https://github.com/hyperledger/aries-rfcs/blob/master/features/0067-didcomm-diddoc-conventions/README.md#service-conventions).
Although published, wallets may only connect to this DID in response to a DIDComm connection invitation. The connection
protocol supported is
[Aries RFC0023 DIDExchange Protocol](https://github.com/hyperledger/aries-rfcs/blob/master/features/0023-did-exchange/README.md).

The governance credentials included in the request accredit the relying party - as identified by their public `trustbloc`
DID - as a participant with a role in a trust framework, and are issued by trusted authorities.


## Credentials Response

The Wallet expects a web credentials response containing a Verifiable Presentation of type
`https://identity.foundation/presentation-exchange/submission/v1`.

```jsonc
{
    "type": "web",
    "dataType": "VerifiablePresentation",
    "data": {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://trustbloc.github.io/context/vp/presentation-exchange-submission-v1.jsonld"
        ],
        "holder": "did:trustbloc:discovery.trustbloc.example.com:EiCYXf7rzJYfVOGnhi1Q-GUZ0vM6f6Tq4t0nb_wwueZ4Yw",
        "type": [
            "VerifiablePresentation",
            "PresentationSubmission"
        ],
        "presentation_submission": {
            // presentation submission object: https://identity.foundation/presentation-exchange/#presentation-submission
        },
        "proof": {
            // verifiable proof
        },
        "verifiableCredential": [
            // list of verifiable credentials
        ]
    }
}
```

<details><summary>Full example</summary>

```json
{
    "type": "web",
    "dataType": "VerifiablePresentation",
    "data": {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://trustbloc.github.io/context/vp/presentation-exchange-submission-v1.jsonld"
        ],
        "holder": "did:trustbloc:discovery.trustbloc.example.com:EiCYXf7rzJYfVOGnhi1Q-GUZ0vM6f6Tq4t0nb_wwueZ4Yw",
        "presentation_submission": {
            "descriptor_map": [
                {
                    "id": "driver_license:local",
                    "path": "$.verifiableCredential[0]"
                },
                {
                    "id": "driver_license_evidence:remote",
                    "path": "$.verifiableCredential[1]"
                }
            ]
        },
        "proof": {
            "created": "2020-10-26T18:34:28.258-04:00",
            "domain": "verifier-adapter.trustbloc.example.com",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..Wx8v53rhgAks8dFLm5M6Cs5vPVgbHvqId2hZ2zs0j7Z2Ts6cxhb_P0HwynyMmk9wk2ZLAoJv4j62-c3wHtr4Bg",
            "proofPurpose": "authentication",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:trustbloc:discovery.trustbloc.example.com:EiCYXf7rzJYfVOGnhi1Q-GUZ0vM6f6Tq4t0nb_wwueZ4Yw#_l5mHlcG8Rz6Z62N1tLiqWxAY4rBoS35iyEuFZ-1p7k"
        },
        "type": [
            "VerifiablePresentation",
            "PresentationSubmission"
        ],
        "verifiableCredential": [
            {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://trustbloc.github.io/context/vc/examples/mdl-v1.jsonld"
                ],
                "type": [
                    "VerifiableCredential",
                    "mDL"
                ],
                "id": "urn:uuid:d1b519eb-c980-40da-82c7-db4495d77049",
                "issuanceDate": "2020-10-26T22:25:21.937228658Z",
                "issuer": {
                    "id": "https://demo-issuer.trustbloc.example.com/didcomm",
                    "name": "TrustBloc - Driving License + Assurance Issuer"
                },
                "name": "Drivers License",
                "description": "Drivers License for John Smith (Issued by Government of Castleham)",
                "credentialSubject": {
                    "birthdate": "1990-01-01",
                    "document_number": "123-456-789",
                    "driving_privileges": "G2",
                    "expiry_date": "2025-05-26",
                    "family_name": "Smith",
                    "given_name": "John",
                    "issue_date": "2020-05-27",
                    "issuing_authority": "Ministry of Transport Ontario",
                    "issuing_country": "Canada",
                    "resident_address": "4726 Pine Street",
                    "resident_city": "Toronto",
                    "resident_postal_code": "A1B 2C3",
                    "resident_state": "Ontario"
                },
                "proof": {
                    "created": "2020-10-26T22:25:22.28387799Z",
                    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..03zhBKQAveQDePwcoUMPowsj5WmYtZdcle0PolRkalBXWw8nYY_LxGJQEcQ8fp9lUbFNkI3hWF2ijpE_xRZXDg",
                    "proofPurpose": "assertionMethod",
                    "type": "Ed25519Signature2018",
                    "verificationMethod": "did:trustbloc:discovery.trustbloc.example.com:EiDhbJFybWBLwZCP58A-dgQRRHXyCIfHA_Au9_AShgUQJw#CoG7IaHn5I4Ji0AcmRFS7Ltzf66YvrKnWwqGcSPkLgY"
                }

            },
            {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld"
                ],
                "type": [
                    "VerifiableCredential",
                    "AuthorizationCredential"
                ],
                "id": "urn:uuid:6c715251-d0bc-44cd-be39-c57c237f382f",
                "issuanceDate": "2020-10-26T22:34:25.693548266Z",
                "issuer": "urn:uuid:5fe5367d-b608-4ae0-9c96-f7b521cf5a3a",
                "credentialSubject": {
                    "id": "urn:uuid:9017cd03-3d50-4554-9eaf-354f87b3f70e",
                    "issuerDIDDoc": {
                        "doc": {
                            "@context": [
                                "https://w3id.org/did/v1"
                            ],
                            "assertionMethod": [
                                "#QS1JDThR8iFru8OVt1_ESQ3vACH9vWpqCUjk3Jgyvgc"
                            ],
                            "authentication": [
                                "#QS1JDThR8iFru8OVt1_ESQ3vACH9vWpqCUjk3Jgyvgc"
                            ],
                            "created": "2020-10-26T22:34:25.662914267Z",
                            "id": "did:peer:1zQmeFUNUg2hu6tQ7U4vUk4AWenqGZGr3wBCSVfXtcjk67xK",
                            "publicKey": [
                                {
                                    "controller": "#id",
                                    "id": "#QS1JDThR8iFru8OVt1_ESQ3vACH9vWpqCUjk3Jgyvgc",
                                    "publicKeyBase58": "2RzhQXGzr4Q8sbEFU1jXRhJLqYr9bvpA5cuot1DTFcT8",
                                    "type": "Ed25519VerificationKey2018"
                                }
                            ],
                            "service": [
                                {
                                    "id": "#agent",
                                    "priority": 0,
                                    "recipientKeys": [
                                        "2RzhQXGzr4Q8sbEFU1jXRhJLqYr9bvpA5cuot1DTFcT8"
                                    ],
                                    "serviceEndpoint": "https://issuer-adapter-didcomm.trustbloc.example.com",
                                    "type": "did-communication"
                                }
                            ],
                            "updated": "2020-10-26T22:34:25.662914267Z"
                        },
                        "id": "did:peer:1zQmeFUNUg2hu6tQ7U4vUk4AWenqGZGr3wBCSVfXtcjk67xK"
                    },
                    "requestingPartyDIDDoc": {
                        "doc": {
                            "@context": [
                                "https://w3id.org/did/v1"
                            ],
                            "assertionMethod": [
                                "#98oGE-VuEqt3lMibQKulB4OJzhRHgzOrao8U_Y16sJA"
                            ],
                            "authentication": [
                                "#98oGE-VuEqt3lMibQKulB4OJzhRHgzOrao8U_Y16sJA"
                            ],
                            "created": "2020-10-26T22:34:24.651560358Z",
                            "id": "did:peer:1zQmTR4Yxqix6cKGx14f21A35XfRc9RDqzpwSoBQxmC13Rio",
                            "publicKey": [
                                {
                                    "controller": "#id",
                                    "id": "#98oGE-VuEqt3lMibQKulB4OJzhRHgzOrao8U_Y16sJA",
                                    "publicKeyBase58": "FmiK1AGLSDYQhxyiJ6zo59VoBBhaU5uCF8ksoGBMCo8M",
                                    "type": "Ed25519VerificationKey2018"
                                }
                            ],
                            "service": [
                                {
                                    "id": "#agent",
                                    "priority": 0,
                                    "recipientKeys": [
                                        "FmiK1AGLSDYQhxyiJ6zo59VoBBhaU5uCF8ksoGBMCo8M"
                                    ],
                                    "serviceEndpoint": "https://verifier-adapter-didcomm.trustbloc.example.com",
                                    "type": "did-communication"
                                }
                            ],
                            "updated": "2020-10-26T22:34:24.651560358Z"
                        },
                        "id": "did:peer:1zQmTR4Yxqix6cKGx14f21A35XfRc9RDqzpwSoBQxmC13Rio"
                    },
                    "subjectDID": "did:peer:1zQme2FTBHheMdfX9CQmX3UjGkUpmLtmP1T3Jbu3Qu8MnW2P"
                },
                "proof": {
                    "created": "2020-10-26T22:34:26.102106902Z",
                    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..1XTTXFb66rS1tGGHPkAurLQe5_WO81G66YUbbxjYSuK10-JfkZrRyOCEgCMnkgb2QZibgwa_gb3kx4LvwjtTAA",
                    "proofPurpose": "assertionMethod",
                    "type": "Ed25519Signature2018",
                    "verificationMethod": "did:trustbloc:discovery.trustbloc.example.com:EiDhbJFybWBLwZCP58A-dgQRRHXyCIfHA_Au9_AShgUQJw#CoG7IaHn5I4Ji0AcmRFS7Ltzf66YvrKnWwqGcSPkLgY"
                }
            }
        ]
    }
}
```
</details>

## Return to service provider

The Adapter will process and verify the [credential response](#credentials-response) and redirect the user's web browser
back to the service provider.
