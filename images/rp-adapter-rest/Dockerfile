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
	npm \
	make;
ADD . src/github.com/trustbloc/edge-adapter
WORKDIR src/github.com/trustbloc/edge-adapter
ENV EXECUTABLES go git

FROM golang as edge-adapter
RUN make rp-adapter-vue adapter-rest

FROM alpine:${ALPINE_VER} as base
COPY --from=edge-adapter /go/src/github.com/trustbloc/edge-adapter/.build/bin/adapter-rest /usr/local/bin
COPY --from=edge-adapter /go/src/github.com/trustbloc/edge-adapter/.build/bin/rp-adapter-vue /usr/local/static/rp-adapter-vue/
ENV ADAPTER_REST_STATIC_FILES=/usr/local/static/rp-adapter-vue
ENV ADAPTER_REST_MODE=rp

# set up nsswitch.conf for Go's "netgo" implementation
# - https://github.com/golang/go/blob/go1.9.1/src/net/conf.go#L194-L275
RUN [ ! -e /etc/nsswitch.conf ] && echo 'hosts: files dns' > /etc/nsswitch.conf

ENTRYPOINT ["adapter-rest"]
