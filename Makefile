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
# Same selection as container.Detect (podman, then docker, with version and
# endpoint preflight). Override with CONTAINER_RUNTIME=docker|podman; the
# override is still probed, not merely taken from PATH. Detection and build
# share one runtime binary; a failed build does not inspect a stale image.

fixture-image:
	@set -eu; \
	if [ -n "$(CONTAINER_RUNTIME)" ]; then \
	  rt=$$($(GO) run ./cmd/detect-runtime/ "$(CONTAINER_RUNTIME)"); \
	else \
	  rt=$$($(GO) run ./cmd/detect-runtime/); \
	fi; \
	test -n "$$rt"; \
	echo "building with $$rt"; \
	"$$rt" build -t "$(FIXTURE_IMAGE)" campaigns/fixture-lab; \
	echo "built with $$rt; container_image for campaign.yaml:"; \
	digest=$$("$$rt" image inspect "$(FIXTURE_IMAGE)" --format '{{index .RepoDigests 0}}'); \
	test -n "$$digest"; \
	echo "$$digest"

clean:
	rm -rf vrh
