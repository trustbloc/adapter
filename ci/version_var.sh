#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


# Release Parameters
BASE_VERSION=0.1.6
IS_RELEASE=true

DOCKER_REPO=ghcr.io
RELEASE_REPO=trustbloc
SNAPSHOT_REPO=trustbloc-cicd

# Project Parameters
SOURCE_REPO=edge-adapter
BASE_ISSUER_ADAPTER_PKG_NAME=issuer-adapter
BASE_RP_ADAPTER_PKG_NAME=rp-adapter
BASE_WALLET_CLIENT_PKG_NAME=wallet-adapter-web

if [ ${IS_RELEASE} = false ]
then
  EXTRA_VERSION=snapshot-$(git rev-parse --short=7 HEAD)
  PROJECT_VERSION=${BASE_VERSION}-${EXTRA_VERSION}
  PROJECT_PKG_REPO=${SNAPSHOT_REPO}
  NPM_WALLET_PKG_REPO=${PROJECT_PKG_REPO}/snapshot
else
  PROJECT_VERSION=${BASE_VERSION}
  PROJECT_PKG_REPO=${RELEASE_REPO}
  NPM_WALLET_PKG_REPO=${PROJECT_PKG_REPO}/${SOURCE_REPO}
fi

export ADAPTER_REST_TAG=$PROJECT_VERSION
export ISSUER_ADAPTER_REST_PKG=${DOCKER_REPO}/${PROJECT_PKG_REPO}/${BASE_ISSUER_ADAPTER_PKG_NAME}
export RP_ADAPTER_REST_PKG=${DOCKER_REPO}/${PROJECT_PKG_REPO}/${BASE_RP_ADAPTER_PKG_NAME}

export NPM_WALLET_PKG_TAG=${PROJECT_VERSION}
export NPM_WALLET_PKG_NAME=${PROJECT_PKG_REPO}/${BASE_WALLET_CLIENT_PKG_NAME}
export NPM_WALLET_PKG_REPO=${NPM_WALLET_PKG_REPO}
