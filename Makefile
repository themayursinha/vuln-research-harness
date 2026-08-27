.PHONY: build test vet fmt check clean

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

fixture-image:
	docker build -t $(FIXTURE_IMAGE) campaigns/fixture-lab
	@echo "container_image for campaign.yaml:"
	@docker image inspect $(FIXTURE_IMAGE) --format '{{index .RepoDigests 0}}' 2>/dev/null || docker image inspect $(FIXTURE_IMAGE) --format '{{.Id}}'

clean:
	rm -rf vrh
