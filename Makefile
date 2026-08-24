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

clean:
	rm -rf vrh
