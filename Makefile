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
# Same selection logic as container.Detect (podman, then docker, with version
# and endpoint preflight). Override with CONTAINER_RUNTIME=docker|podman.
CONTAINER_RUNTIME ?= $(shell $(GO) run ./cmd/detect-runtime/ 2>/dev/null)

fixture-image:
	@test -n "$(CONTAINER_RUNTIME)" || (echo "no container runtime (podman or docker)" >&2; exit 1)
	$(CONTAINER_RUNTIME) build -t $(FIXTURE_IMAGE) campaigns/fixture-lab
	@echo "built with $(CONTAINER_RUNTIME); container_image for campaign.yaml:"
	@$(CONTAINER_RUNTIME) image inspect $(FIXTURE_IMAGE) --format '{{index .RepoDigests 0}}' 2>/dev/null \
		|| $(CONTAINER_RUNTIME) image inspect $(FIXTURE_IMAGE) --format '{{.Id}}'

clean:
	rm -rf vrh
