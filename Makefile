.PHONY: build test vet fmt check clean fixture-image mcp-filesystem-image

GO ?= go

build:
	$(GO) build ./cmd/vrh/

test:
	$(GO) test ./... -count=1 -timeout 120s

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

check: vet test build

FIXTURE_IMAGE ?= localhost/vrh-fixture-lab:latest
MCP_FILESYSTEM_IMAGE ?= localhost/vrh-mcp-filesystem:latest
# Builds via cmd/fixture-image: same Detect/DetectKind preflight and sanitized
# clientEnv as vrh repro (local unix socket, no DOCKER_CONTEXT). Override with
# CONTAINER_RUNTIME=docker|podman.

fixture-image:
	CONTAINER_RUNTIME="$(CONTAINER_RUNTIME)" $(GO) run ./cmd/fixture-image/ -image "$(FIXTURE_IMAGE)"

mcp-filesystem-image:
	CONTAINER_RUNTIME="$(CONTAINER_RUNTIME)" $(GO) run ./cmd/fixture-image/ -image "$(MCP_FILESYSTEM_IMAGE)" -context campaigns/mcp-filesystem

clean:
	rm -rf vrh
