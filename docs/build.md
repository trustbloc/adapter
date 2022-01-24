# Building and Testing

## Prerequisites
- Go 1.17
- Docker
- Docker-Compose
- Make
- bash
- npm v7  

## Host file
Add following entries to the host file.

```
127.0.0.1 testnet.orb.local
127.0.0.1 issuer-adapter-rest.trustbloc.local
127.0.0.1 issuer-hydra.trustbloc.local
127.0.0.1 mock-issuer-login.trustbloc.local
```

## Targets

```
# run everything
make all

# linters
make checks

# unit tests
make unit-test

# BDD tests
make bdd-test
```
