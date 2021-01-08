# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

ADAPTER_REST_PATH=cmd/adapter-rest

# Namespace for the agent images
DOCKER_OUTPUT_NS   ?= ghcr.io
ADAPTER_REST_BASE_IMAGE_NAME ?= trustbloc/edge-adapter/adapter-base
ISSUER_ADAPTER_REST_IMAGE_NAME   ?= trustbloc/issuer-adapter
RP_ADAPTER_REST_IMAGE_NAME   ?= trustbloc/rp-adapter
MOCK_ISSUER_IMAGE_NAME ?= trustbloc/edge-adapter/mock-issuer
MOCK_WEBHOOK_IMAGE_NAME ?= trustbloc/edge-adapter/mock-webhook

# Tool commands (overridable)
ALPINE_VER ?= 3.12
GO_VER ?= 1.15
GOBIN_PATH=$(abspath .)/.build/bin

.PHONY: all
all: checks unit-test bdd-test

.PHONY: checks
checks: license lint

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: issuer-adapter-vue
issuer-adapter-vue:
	@echo "Building issuer-adapter-vue frontend"
	@mkdir -p ./.build/bin/issuer-adapter-vue
	@npm --prefix cmd/issuer-adapter-vue install
	@npm --prefix cmd/issuer-adapter-vue run build
	@cp -rp cmd/issuer-adapter-vue/dist/* ./.build/bin/issuer-adapter-vue

.PHONY: rp-adapter-vue
rp-adapter-vue:
	@echo "Building rp-adapter-vue frontend"
	@mkdir -p ./.build/bin/rp-adapter-vue
	@npm --prefix cmd/rp-adapter-vue install
	@npm --prefix cmd/rp-adapter-vue run build
	@cp -rp cmd/rp-adapter-vue/dist/* ./.build/bin/rp-adapter-vue

.PHONY: adapter-rest
adapter-rest:
	@echo "Building adapter-rest"
	@mkdir -p ./.build/bin
	@GO111MODULE=off GOBIN=$(GOBIN_PATH) go get github.com/myitcv/gobin
	@cd ${ADAPTER_REST_PATH} && $(GOBIN_PATH)/gobin -run github.com/gobuffalo/packr/v2/packr2@v2.8.0 build -o ../../.build/bin/adapter-rest main.go

.PHONY: adapter-rest-docker-base
adapter-rest-docker-base:
	@echo "Building adapter rest docker base image"
	@docker build -f ./images/adapter-rest-base/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(ADAPTER_REST_BASE_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: issuer-adapter-rest-docker
issuer-adapter-rest-docker: adapter-rest-docker-base issuer-adapter-vue
	@echo "Building issuer adapter rest docker image"
	@docker build -f ./images/issuer-adapter-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(ISSUER_ADAPTER_REST_IMAGE_NAME):latest \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: rp-adapter-rest-docker
rp-adapter-rest-docker: adapter-rest-docker-base rp-adapter-vue
	@echo "Building rp adapter rest docker image"
	@docker build -f ./images/rp-adapter-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(RP_ADAPTER_REST_IMAGE_NAME):latest \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: bdd-test
bdd-test: clean rp-adapter-rest-docker issuer-adapter-rest-docker mock-issuer-docker mock-webhook-docker generate-test-config generate-test-keys
	@scripts/check_integration.sh

.PHONY: generate-test-config
generate-test-config:
	@scripts/generate_test_config.sh

.PHONY: generate-test-keys
generate-test-keys: clean
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/edge-adapter \
		--entrypoint "/opt/workspace/edge-adapter/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: mock-issuer
mock-issuer:
	@echo "Building mock issuer server"
	@mkdir -p ./.build/bin
	@go build -o ./.build/bin/issuer-server test/mock/cmd/issuer/main.go

.PHONY: mock-issuer-docker
mock-issuer-docker:
	@echo "Building mock issuer server docker image"
	@docker build -f ./test/mock/images/issuer/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(MOCK_ISSUER_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) \
	--build-arg GO_TAGS=$(GO_TAGS) \
	--build-arg GOPROXY=$(GOPROXY) .

.PHONY: mock-webhook
mock-webhook:
	@echo "Building mock webhook server"
	@mkdir -p ./build/bin
	@go build -o ./build/bin/webhook-server test/mock/cmd/webhook/main.go

.PHONY: mock-webhook-docker
mock-webhook-docker:
	@echo "Building mock webhook server docker image"
	@docker build -f ./test/mock/images/webhook/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(MOCK_WEBHOOK_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) \
	--build-arg GO_TAGS=$(GO_TAGS) \
	--build-arg GOPROXY=$(GOPROXY) .

.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
	@rm -Rf ./test/bdd/fixtures/keys/tls
	@rm -Rf ./test/bdd/docker-compose.log
