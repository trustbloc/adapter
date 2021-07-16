#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG ALPINE_VER

FROM ghcr.io/trustbloc/edge-adapter/adapter-base:latest as base

FROM alpine:${ALPINE_VER}
LABEL org.opencontainers.image.source https://github.com/trustbloc/adapter

COPY --from=base /go/src/github.com/trustbloc/edge-adapter/.build/bin/adapter-rest /usr/local/bin
COPY .build/bin/issuer-adapter-vue /usr/local/static/issuer-adapter-vue/
ENV ADAPTER_REST_STATIC_FILES=/usr/local/static/issuer-adapter-vue/
ENV ADAPTER_REST_MODE=issuer

# set up nsswitch.conf for Go's "netgo" implementation
# - https://github.com/golang/go/blob/go1.9.1/src/net/conf.go#L194-L275
RUN [ ! -e /etc/nsswitch.conf ] && echo 'hosts: files dns' > /etc/nsswitch.conf

ENTRYPOINT ["adapter-rest"]
