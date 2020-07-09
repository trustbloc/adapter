#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${ALPINE_VER} as golang
RUN apk add --no-cache \
	gcc \
	musl-dev \
	git \
	libtool \
	bash \
	make;

ADD . src/github.com/trustbloc/edge-adapter
WORKDIR src/github.com/trustbloc/edge-adapter
ENV EXECUTABLES go git

FROM golang as edge-adapter
RUN make mock-issuer

FROM alpine:${ALPINE_VER} as base
COPY --from=edge-adapter /go/src/github.com/trustbloc/edge-adapter/.build/bin/issuer-server /usr/local/bin
CMD ISSUER_PORT=${ISSUER_PORT} issuer-server
