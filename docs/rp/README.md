# RP Adapter

The Relying Party (RP) Adapter enables standard OpenID Connect flows on top of DIDComm.
It exposes a standard OpenID Connect provider service and transparently handles the mechanics of DIDComm on behalf of
relying parties. Behind the scene, RP Adapter uses [DIF Wallet And Credential Interaction with DIDComm v2](https://identity.foundation/waci-presentation-exchange/) 
specification to communicate with Wallet.

![overview](./rp_adapter_overview.svg)

## Components
- [RP Adapter Core](../../cmd/adapter-rest)
- [ORY Hydra](https://github.com/ory/hydra/blob/master/README.md)

## Integration
- [Relying Party](./integration/relying_parties.md)