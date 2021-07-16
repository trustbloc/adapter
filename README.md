[![Release](https://img.shields.io/github/release/trustbloc/edge-adapter.svg?style=flat-square)](https://github.com/trustbloc/edge-adapter/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/edge-adapter/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/edge-adapter)

[![Build Status](https://github.com/trustbloc/adapter/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/trustbloc/adapter/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/trustbloc/adapter/branch/main/graph/badge.svg)](https://codecov.io/gh/trustbloc/adapter)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/edge-adapter)](https://goreportcard.com/report/github.com/trustbloc/edge-adapter)

# Adapter

The TrustBloc Adapter acts as an intermediary between RP/Issuer components to support [DIDComm](https://github.com/hyperledger/aries-rfcs/tree/master/concepts/0005-didcomm) 
operations. The edge-adapter uses the capabilities provided by [Hyperledger Aries Framework Go](https://github.com/hyperledger/aries-framework-go) 
such as DIDComm, [W3C Verifiable Credentials(VC)](https://w3c.github.io/vc-data-model/), [W3C Decentralized Identifiers(DIDs)](https://w3c.github.io/did-core/), etc.

The Adapter contains following components.
- [Issuer Adapter](./docs/issuer/README.md)
- [Relying Party (RP) Adapter](./docs/rp/README.md) 

The TrustBloc Adapters provide support for DIDComm to go through a router using [Blinded Routing](./docs/blinded_routing.md) feature. 

## Build
To build from source see [here](docs/build.md).

## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/main/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
