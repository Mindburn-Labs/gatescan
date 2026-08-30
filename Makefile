# GOWORK=off: this repo must build standalone, not through the workspace go.work.
GO := GOWORK=off go

.PHONY: build test vet fmt check demo clean

build:
	$(GO) build ./...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

check: build vet test
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:" >&2; echo "$$out" >&2; exit 1; fi

# Scan the bundled synthetic fixtures and write report.json / report.html here.
demo:
	$(GO) run ./cmd/gatescan scan fixtures

clean:
	rm -f report.json report.html gatescan
