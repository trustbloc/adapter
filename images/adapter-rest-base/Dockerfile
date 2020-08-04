#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${ALPINE_VER}
RUN apk add --no-cache git make
ADD . src/github.com/trustbloc/edge-adapter
WORKDIR src/github.com/trustbloc/edge-adapter
RUN make adapter-rest
