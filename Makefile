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
all: checks unit-test adapter-vue adapter-rest-docker

.PHONY: checks
checks: license lint

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: adapter-vue
adapter-vue:
	@echo "Building adapter-vue frontend"
	@mkdir -p ./.build/bin/adapter-vue
	@npm --prefix cmd/adapter-vue install
	@npm --prefix cmd/adapter-vue run build
	@cp -rp cmd/adapter-vue/dist/* ./.build/bin/adapter-vue

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

.PHONY: bdd-test
bdd-test: clean adapter-rest-docker generate-test-keys
	@scripts/check_integration.sh


.PHONY: generate-test-keys
generate-test-keys: clean
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/edge-adapter \
		--entrypoint "/opt/workspace/edge-adapter/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
	@rm -Rf ./test/bdd/fixtures/keys/tls
	@rm -Rf ./test/bdd/docker-compose.log
