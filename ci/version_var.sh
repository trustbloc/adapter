#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


# Release Parameters
BASE_VERSION=0.1.6
IS_RELEASE=false

# Project Parameters
SOURCE_REPO=edge-adapter
BASE_ISSUER_ADAPTER_PKG_NAME=issuer-adapter
BASE_RP_ADAPTER_PKG_NAME=rp-adapter
RELEASE_REPO=ghcr.io/trustbloc
SNAPSHOT_REPO=ghcr.io/trustbloc-cicd

if [ ${IS_RELEASE} = false ]
then
  EXTRA_VERSION=snapshot-$(git rev-parse --short=7 HEAD)
  PROJECT_VERSION=${BASE_VERSION}-${EXTRA_VERSION}
  PROJECT_PKG_REPO=${SNAPSHOT_REPO}
else
  PROJECT_VERSION=${BASE_VERSION}
  PROJECT_PKG_REPO=${RELEASE_REPO}
fi

export ADAPTER_REST_TAG=$PROJECT_VERSION
export ISSUER_ADAPTER_REST_PKG=${PROJECT_PKG_REPO}/${BASE_ISSUER_ADAPTER_PKG_NAME}
export RP_ADAPTER_REST_PKG=${PROJECT_PKG_REPO}/${BASE_RP_ADAPTER_PKG_NAME}
