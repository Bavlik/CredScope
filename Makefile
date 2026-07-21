GO ?= go
BINARY := .tmp-build/credscope
REPORT_DIR := .tmp-reports

.PHONY: fmt test test-race vet vuln lint build smoke reports verify release-snapshot clean

fmt:
	gofmt -w $$(find cmd internal pkg scripts -name '*.go' -type f)

test:
	$(GO) test -count=1 ./...

test-race:
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

vuln:
	govulncheck ./...

lint:
	test -z "$$(gofmt -l cmd internal pkg scripts)"
	$(GO) vet ./...

build:
	mkdir -p .tmp-build
	$(GO) build -trimpath -o $(BINARY) ./cmd/credscope

smoke: build
	$(BINARY) version
	$(BINARY) rules list >/dev/null
	$(BINARY) scan testdata/safe --format json >/dev/null

reports: build
	mkdir -p $(REPORT_DIR)
	$(BINARY) scan testdata/vulnerable --gitleaks-report gitleaks.json --format json >$(REPORT_DIR)/credscope.json
	$(BINARY) scan testdata/vulnerable --gitleaks-report gitleaks.json --format sarif >$(REPORT_DIR)/credscope.sarif
	$(BINARY) scan testdata/vulnerable --gitleaks-report gitleaks.json --format html >$(REPORT_DIR)/credscope.html
	$(BINARY) scan testdata/vulnerable --gitleaks-report gitleaks.json --format mermaid >$(REPORT_DIR)/blast-radius.md
	$(GO) run ./scripts/verify-reports.go $(REPORT_DIR)

verify: lint test vet build smoke reports
	$(GO) mod verify
	git diff --check

release-snapshot:
	BUILD_DATE=$$(git show -s --format=%cI HEAD) goreleaser release --snapshot --clean

clean:
	rm -rf .tmp-build .tmp-reports dist
