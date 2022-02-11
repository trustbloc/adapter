# Integration Guide for Issuers

## Purpose of this document

This document serves as a guide for integrating REST APIs with Issuer Adapter. Issuer Adapter acts as 
a [OpenID Connect 1.0](https://openid.net/specs/openid-connect-core-1_0.html) client when interacting with 
the Issuer. The reader is expected to be familiar with OIDC and the OAuth2 authorization code flow.

## Flow diagram
TODO

## Steps
Follow these steps to integrate as a Issuer:

1. [Register a client/profile](#register-a-clientprofile)
2. [Redirect the user to Adapter API](#redirect-the-user-to-adapter-api)
3. [Handle Auth Request](#process-auth-callback)
4. [Support Data Endpoint](#process-user-data-call)
5. [Handle Post process redirect](#handle-success-page)

### Register a Client/Profile

Register a client/profile with Issuer adapter.

**Request:**

```jsonc
HTTP POST <issuer-adapter-url>/profile

{
    "id": "tb-prc-issuer1",
    "name":"TrustBloc Demo - Permanent Resident Card Issuer",
    "url": "https://demo-issuer.sandbox.trustbloc.dev/didcomm",
    "oidcProvider": "https://hydra.sandbox.trustbloc.dev/",
    "scopes": [
        "PermanentResidentCard"
    ],
    "supportedVCContexts": [
        "https://w3id.org/citizenship/v1"
    ],
    "supportsWACI": true,
    "linkedWallet": "https://wallet.sandbox.trustbloc.dev/waci"
}
```

| Parameter           | Type             | Description                                                                                                                               | Required                | Default |
|---------------------|------------------|-------------------------------------------------------------------------------------------------------------------------------------------|-------------------------|---------|
| id                  | string           | unique profile id                                                                                                                         |                         |         |
| name                | string           | Issuer name                                                                                                                               | Y                       |         |
| url                 | string           | Issuer callback URL base                                                                                                                  | Y                       |         |
| scopes              | array of strings | The list of supported scopes. See notes on [available scopes](#available-scopes) for how to discover the scopes supported by the adapter. | Y                       |         |
| supportsWACI        | bool             | Enable WACI flow with Wallet. If this is not set, then adapter will use CHAPI flow.                                                       | N                       | false   |
| linkedWalletURL     | string           | URL of the wallet                                                                                                                         | Y, if supportsWACI=true |         |
| supportedVCContexts | array of strings | **DEPRECATED** this will be removed in future version. for now, send any string.                                                          |                         |         |

**Response:**


```jsonc
HTTP 201 CREATED

{
   "id":"tb-prc-issuer2",
   "name":"TrustBloc Demo - Permanent Resident Card Issuer",
   "url":"https://demo-issuer.sandbox.trustbloc.dev/didcomm",
   "supportedVCContexts":[
      "https://w3id.org/citizenship/v1"
   ],
   "credentialSigningKey":"did:orb:uAAA:EiARcLmkKrStI_3_Fof6YcB6dnjIXWlKClhp-HeBb7kmRg#S7MjMEUQRconE-A5op9k3Exd9Enn8EJmfRx8baGiCvM",
   "presentationSigningKey":"did:orb:uAAA:EiARcLmkKrStI_3_Fof6YcB6dnjIXWlKClhp-HeBb7kmRg#S7MjMEUQRconE-A5op9k3Exd9Enn8EJmfRx8baGiCvM",
   "createdAt":"2022-02-09T18:32:27.807343657Z",
   "supportsWACI":true,
   "oidcProvider":"https://hydra.sandbox.trustbloc.dev/",
   "credScopes":[
      "PermanentResidentCard"
   ],
   "linkedWallet":"https://wallet.sandbox.trustbloc.dev/waci"
}
```

### Redirect the user to Adapter API
Invoke following url from Issuer application to start the flow.

```
<issuer-adapter-url>/<profile-id>/connect/wallet?cred=<scope>&txnID=<uuid>
```

Note:
- `profile-id` : profile id from registration step
- `cred`: value shoule be from scopes request param from [registration request](#register-a-clientprofile)

### Process Auth Callback
The issuer adapter calls OIDC auth endpoint of the issuer.

```
<issuer-oidc-provider-url>/oauth2/auth?access_type=offline&client_id=e507f0c6-bd60-4d51-a02f-089c570167c8&redirect_uri=https%3A%2F%2Fadapter-issuer.sandbox.trustbloc.dev%2Foidc%2Fcb&response_type=code&scope=openid+offline_access+PermanentResidentCard&state=BMC8ZeVHMMqlMUgKYTlA6GPGlAxctx2Q
```

Once auth call has been process, redirect to adapter based on `redirect_uri` value from auth call request.

Note:
- `issuer-oidc-provider-url` : oidc auth url based on `oidcProvider` in registration request.
- `code` : oidc auth code

### Process User Data call
Invoke token endpoint to exchange code for access_token and id_token. The id_token in the response will contain the user data inside claims. The 
use of OIDC client in programming langugae is preffered to generate the OIDC auth request.

#### Request

```bash
HTTP POST
curl --location --request POST '<issuer-url-from-profile>/data' \
--header 'Content-Type: application/json' \
--data-raw '{
    "token": "<code_from_auth_response>"
}'
```

Note:
- `issuer-url-from-profile` : this would be the `url` param set during registration.

#### Respone

```json
{
	   "data":{
		  "id":"http://example.com/b34ca6cd37bbf23",
		  "givenName":"JOHN",
		  "familyName":"SMITH",
		  "gender":"Male",
		  "image":"data:image/png;base64,iVBORw0KGgo...kJggg==",
		  "residentSince":"2015-01-01",
		  "lprCategory":"C09",
		  "lprNumber":"999-999-999",
		  "commuterClassification":"C1",
		  "birthCountry":"Bahamas",
		  "birthDate":"1958-07-17"
	   },
	   "metadata":{
		  "contexts":["https://trustbloc.github.io/context/vc/examples/citizenship-v1.jsonld"],
		  "scopes":["PermanentResidentCard"],
		  "name":"Permanent Resident Card",
		  "description":"Permanent Resident Card for John Smith"
	   }
	}
```

Note:
- `data` : this will be part of credentialSubject inside Verifiable Credential.

### Handle Success Page

````
HTTP Redirect
<issuer-url-from-profile>/cb?txnID=<txnID_from_initial_call>
````

Note:
- `issuer-oidc-provider-url` : oidc auth url based on `oidcProvider` in registration request.

## Available Scopes

The scopes the Adapter supports are currently configured in a simple
[JSON format](../../../test/bdd/fixtures/testdata/manifest-config/cmdescriptors.json)
that is not exposed in via any other means. Consult the system administrator for the currently supported scopes before
[registering the client](#register-a-clientprofile).
