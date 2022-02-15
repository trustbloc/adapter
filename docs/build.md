# Building and Testing

## Prerequisites
- [Go 1.17](https://go.dev/doc/install)
- [Docker](https://docs.docker.com/get-docker/) (make sure to set your `Docker` to use `Docker-Compose V1`)
- [Docker-Compose V1](https://docs.docker.com/compose/install/)
- [npm v8](https://docs.npmjs.com/cli/v8/configuring-npm/install)  
- GitHub packages setup: you will need to authenticate to GitHub packages with your [personal token](https://help.github.com/en/github/authenticating-to-github/creating-a-personal-access-token-for-the-command-line#creating-a-token).
- Configuring npm for use with GitHub Packages echo "//npm.pkg.github.com/:_authToken=${PERSONAL_TOKEN}" > ~/.npmrc
- Make
- bash


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
