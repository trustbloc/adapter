# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

ADAPTER_REST_PATH=cmd/adapter-rest

# Namespace for the agent images
DOCKER_OUTPUT_NS   ?= docker.pkg.github.com
ADAPTER_REST_IMAGE_NAME   ?= trustbloc/edge-adapter/adapter-rest

# Tool commands (overridable)
ALPINE_VER ?= 3.11
GO_VER ?= 1.14

.PHONY: all
all: checks unit-test

.PHONY: checks
checks: license lint

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: adapter-rest
adapter-rest:
	@echo "Building adapter-rest"
	@mkdir -p ./.build/bin
	@cd ${ADAPTER_REST_PATH} && go build -o ../../.build/bin/adapter-rest main.go

.PHONY: adapter-rest-docker
adapter-rest-docker:
	@echo "Building adapter rest docker image"
	@docker build -f ./images/adapter-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(ADAPTER_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
