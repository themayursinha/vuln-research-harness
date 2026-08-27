.PHONY: build test vet fmt check clean fixture-image

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
# Same preference order as container.Detect (podman, then docker). Override with
# CONTAINER_RUNTIME=docker|podman when both are installed and you need a specific one.
CONTAINER_RUNTIME ?= $(shell \
	if command -v podman >/dev/null 2>&1; then echo podman; \
	elif command -v docker >/dev/null 2>&1; then echo docker; \
	else echo ""; fi)

fixture-image:
	@test -n "$(CONTAINER_RUNTIME)" || (echo "no container runtime (podman or docker)" >&2; exit 1)
	$(CONTAINER_RUNTIME) build -t $(FIXTURE_IMAGE) campaigns/fixture-lab
	@echo "built with $(CONTAINER_RUNTIME); container_image for campaign.yaml:"
	@$(CONTAINER_RUNTIME) image inspect $(FIXTURE_IMAGE) --format '{{index .RepoDigests 0}}' 2>/dev/null \
		|| $(CONTAINER_RUNTIME) image inspect $(FIXTURE_IMAGE) --format '{{.Id}}'

clean:
	rm -rf vrh
