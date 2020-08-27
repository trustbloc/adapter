# RP Adapter: Standards & Technologies

The RP Adapter implements emerging standards and technologies to achieve secure, confidential, noncorrelatable
transactions between relying parties and identity providers mediated by the end user.

## Technologies

* [Hyperledger Aries Framework - Go](https://github.com/hyperledger/aries-framework-go/blob/master/README.md)
* [Credential Handler API polyfill](https://github.com/digitalbazaar/credential-handler-polyfill/blob/master/README.md)

Note: for an overview of the tech stack, see [stack](./architecture.md#stack).

## Standards

* [Verifiable Credentials Data Model 1.0](https://www.w3.org/TR/vc-data-model/)
* [Decentralized Identifiers (DIDs) v1.0](https://w3c.github.io/did-core/)
  * [TrustBloc DID Method Specification 0.1](https://github.com/trustbloc/trustbloc-did-method/blob/master/docs/spec/trustbloc-did-method.md)
  * [Peer DID Method Specification](https://identity.foundation/peer-did-method-spec/)
* Hyperledger Aries RFCs:
  * [RFC0005 - DID Communication](https://github.com/hyperledger/aries-rfcs/blob/master/concepts/0005-didcomm/README.md) ("DIDComm")
  * [RFC0434 - Out-of-Band Protocols](https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md)
  * [RFC0023 - DID Exchange Protocol 1.0](https://github.com/hyperledger/aries-rfcs/blob/master/features/0023-did-exchange/README.md)
  * [RFC0453 - Issue Credential Protocol 2.0](https://github.com/hyperledger/aries-rfcs/blob/master/features/0453-issue-credential-v2/README.md)
  * [RFC0454 - Present Proof Protocol 2.0](https://github.com/hyperledger/aries-rfcs/blob/master/features/0454-present-proof-v2/README.md)
  * [RFC0017 - Attachments](https://github.com/hyperledger/aries-rfcs/blob/master/concepts/0017-attachments/README.md)
  * [RFC0067 - DIDComm DID document conventions](https://github.com/hyperledger/aries-rfcs/blob/master/features/0067-didcomm-diddoc-conventions/README.md)
* Decentralized Identity Foundation's [Presentation-Exchange](https://identity.foundation/presentation-exchange/)
* OpenID Connect:
    * [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
    * [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
    * [OpenID Connect for Identity Assurance 1.0](https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html)
