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
# Detection runs once inside the recipe (not via recursive ?= expansion).

fixture-image:
	@rt='$(CONTAINER_RUNTIME)'; \
	if [ -z "$$rt" ]; then \
	  rt=$$($(GO) run ./cmd/detect-runtime/) || { echo "no container runtime (podman or docker)" >&2; exit 1; }; \
	fi; \
	echo "building with $$rt"; \
	$$rt build -t $(FIXTURE_IMAGE) campaigns/fixture-lab; \
	echo "built with $$rt; container_image for campaign.yaml:"; \
	$$rt image inspect $(FIXTURE_IMAGE) --format '{{index .RepoDigests 0}}' 2>/dev/null \
		|| $$rt image inspect $(FIXTURE_IMAGE) --format '{{.Id}}'

clean:
	rm -rf vrh
