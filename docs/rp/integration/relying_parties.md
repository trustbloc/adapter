# Integration Guide for Relying Parties

## Purpose of this document

This document serves as a guide for integrating [OpenID Connect 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
client systems to the RP Adapter. The reader is expected to be familiar with OIDC and the OAuth2 authorization code flow.

## Flow diagram

```mermaid
sequenceDiagram
    participant rp as rp/verifier
    participant rp_adapter_core as rp adapter core
    participant rp_adapter_oidc as rp adapter oidc (hydra)
    rp->>rp_adapter_core: register client (one time)
    rp->>rp_adapter_oidc: oidc auth redirect
    rp_adapter_oidc->>rp: oidc auth callback
    rp->>rp_adapter_oidc: oidc token endpoint
    rp_adapter_oidc->>rp: id_token with user data
```

## Steps

Follow these steps to integrate as a relying party:

1. [Register a client](#register-oidc-client)
2. [Redirect the user with OIDC request](#request-end-user-credentials)
3. Exchange auth code for the `access_token` and [parse the id_token](#id-token)

### Register OIDC Client

Register OIDC client with RP adapter.

**Request:**

```jsonc
HTTP POST <rp-adapter-core-url>/relyingparties

{
   "label":"Acme University",
   "callback":"http://example.acme.edu/oauth2/callback",
   "scopes":[
      "openid",
      "book",
      "newspaper"
   ],
   "supportsWACI":true,
   "linkedWalletURL":"http://wallet.com/"
}
```

| Parameter       | Type             | Description                                                                                                                                                                                                                              | Required                | Default |
|-----------------|------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------|---------|
| label           | string           | A human-readable string describing the client. This label is included in DIDComm invitations sent to end-user wallets.                                                                                                                   | Y                       |         |
| callback        | string           | OIDC callback URL                                                                                                                                                                                                                        | Y                       |         |
| scopes          | array of strings | The list of scopes the RP can request. Note: you **must** include the `openid` scope in order to register as an OIDC client. See notes on [available scopes](#available-scopes) for how to discover the scopes supported by the adapter. | Y                       |         |
| supportsWACI    | bool             | Enable WACI flow with Wallet. If this is not set, then adapter will use CHAPI flow.                                                                                                                                                      | N                       | false   |
| linkedWalletURL | string           | URL of the wallet                                                                                                                                                                                                                        | Y, if supportsWACI=true |         |

**Response:**


```jsonc
HTTP 201 CREATED

{
    "clientID": "75095612-d5c4-44ee-a824-6ec50578b825",
    "clientSecret": "rGDy~Fwf8Hocym8y1q5~da5IV9",
    "requiresBlindedRoute":true,
    "publicDID": "did:trustbloc:testnet.trustbloc.local:EiAZRRfUgI9qnsUdYyL9dY40I5JOOJjQURgXFQ5HzYjGeQ"
}
```

| Parameter    | Type             | Description                                                                                                                                                                                                       |
|--------------|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| clientID     | string           | OIDC client id                                                                                                                                                                                                    |
| clientSecret | string           | OIDC client secret                                                                                                                                                                                                |
| publicDID    | array of strings | A public [Decentralized Identifiers (DID)](https://openid.net/specs/openid-connect-core-1_0.html) created and assigned to your client. Read more about how the adapter uses DIDs in the[note below](#use-of-dids) |

### Request End-User Credentials

Redirect the end-user to the OIDC authorization endpoint (see note [below](#oidc-discovery) on how to discover this endpoint)
and include any or all scopes your client was registered with in the [registration step](#register-your-oidc-client).
*You must also include the `openid` scope in the authorization request*.

The Adapter will authenticate the end-user and request verifiable credentials (and optionally request authorization to access
credentials at other locations reachable via DIDComm).

**Request:**

```jsonc
HTTP GET <rp-adapter-hydra>/oauth2/auth?state=123&scope=openid%20drivers_license%20banking_info
```

### Parsing the End-User Claims

#### ID Token

The end-user claims are grouped per scope and delivered as OIDC aggregate claims.

The Adapter presents the claims following the `verified_claims` schema of
[OpenID Connect for Identity Assurance 1.0](https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html).

Moreover, each member value of `_claim_sources` is a `verified_claims` object and _not_ a JWT as per the
[OIDC standard](https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims).

See the [notes below](#representation-of-oidc-aggregate-claims) for more about the rationale behind the decision to
structure the aggregate claims this way.

Example id_token:

```json
{                                                                                                                                                                                                                  
    "aud": [ 
        "7a16ad61-f561-4bda-819d-71922a39fc5b"
    ],
    "auth_time": 1598311017,
    "at_hash": "L1eTjFL7TncgYiyEtBeqww",
    "exp": 1598314620,
    "iat": 1598311020,
    "iss": "https://localhost:4444/",
    "jti": "5343d94c-7816-4c7d-aae3-009a3fe05886",
    "nonce": "",
    "rat": 1598311017,
    "sid": "2140c597-90a3-4a5b-b331-9decfd73677c",

    "sub": "e49b2ca2-340d-4660-b214-797f05b918a5",

    "_claim_names": {
        "university_degree": "src1",
        "driver_license": "src2"
    },
    "_claim_sources": {
        "src1": {
            "claims": {
                "degreeType": "Bachelors",
                "degreeName": "Computer Science",
                "year": "2020-08-26"
            }
        },
        "src2": {
            "claims": {
                "document_number": "123-456-789",
                "family_name": "Smith",
                "given_name": "John"
            }
        }
    }
}
```

> **TODO:** standard claims not supported yet

#### UserInfo

> **TODO:** /userinfo not supported yet

## Notes

### Use of DIDs

The RP Adapter uses public DIDs to _bootstrap_ secure ["DID Communications" (DIDComm)](https://github.com/hyperledger/aries-rfcs/blob/master/concepts/0005-didcomm/README.md),
or "connections", with end-user wallets. However, establishing connections with each user results in a fresh new pair of
private [peer DIDs](https://identity.foundation/peer-did-method-spec/) known only between the adapter and the end user.

The RP Adapter also uses peer DIDs when establishing connections with remote DIDComm-aware credential servers.

### OIDC Discovery

The RP Adapter provides a standard [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) endpoint
that your client software can use to discover the authorization, token, and userinfo endpoints.

### Representation of OIDC Aggregate Claims

Two mayor goals of the Adapter's design are:

* do not reveal the identities of relying parties to resource servers/identity providers and vice-versa
* encapsulate the mechanics of DIDComm and [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) from clients

The first goal preempts the use of JWTs since the signatures will be meaningless to the relying parties, and will weaken
this "blinding" guarantee.

The second goal presents a more subtle obstacle for the use of JWTs: the Adapter mediates between an OIDC relying party
and DIDComm-aware nodes: end-user agents, authorization servers, and resources servers. The claims and authorization tokens
exchanged between these DIDComm-aware nodes are [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/), which
may be in either [JSON-LD](https://json-ld.org/) or JWT format. It is impossible for the Adapter to unilaterally transform
a JSON-LD document into a JWT while preserving the cryptographic security guarantees.

### Available Scopes

The scopes the Adapter supports are currently configured in a simple
[JSON format](../../../test/bdd/fixtures/testdata/presentationdefinitions.json)
that is not exposed in via any other means. Consult the system administrator for the currently supported scopes before
[registering client](#register-oidc-client).
