.PHONY: all build install clean test test-report fmt vet shadow lint vuln gosec gitleaks cyclomatic cognitive check tools release version tag

BINARY      := mcp-ox-security
PREFIX      ?= $(HOME)/.local/bin
REPORTS_DIR := reports

VERSION ?= $(shell \
	if git describe --tags --exact-match >/dev/null 2>&1; then \
		git describe --tags --exact-match; \
	else \
		echo "$$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)-dev-$$(date +%m%d%H%M)"; \
	fi)
LDFLAGS := -s -w -X main.version=$(VERSION)

all: check build

## tools: Install development tools
tools:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
	go install github.com/uudashr/gocognit/cmd/gocognit@latest
	go install golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install gotest.tools/gotestsum@latest
	go install github.com/boumenot/gocover-cobertura@latest

## build: Compile binary
build:
	go build -ldflags '$(LDFLAGS)' -o build/$(BINARY) .

## fmt: Format code
fmt:
	gofmt -s -w .

## vet: Run go vet
vet:
	go vet ./...

## shadow: Check for variable shadowing
shadow:
	go vet -vettool=$$(go env GOPATH)/bin/shadow ./...

## lint: Run staticcheck
lint:
	staticcheck ./...

## vuln: Run govulncheck
vuln:
	govulncheck ./...

## gosec: Security-focused static analysis
gosec:
	gosec -quiet ./...

## gitleaks: Scan for secrets
gitleaks:
	gitleaks detect --no-git -v

## cyclomatic: Check cyclomatic complexity (threshold: 15)
cyclomatic:
	@output=$$(gocyclo -over 15 .); \
	if [ -n "$$output" ]; then \
		echo "Cyclomatic complexity over 15:"; \
		echo "$$output"; \
		exit 1; \
	fi
	@gocyclo -avg . | grep '^Average'

## cognitive: Check cognitive complexity (threshold: 15)
cognitive:
	@output=$$(gocognit -over 15 .); \
	if [ -n "$$output" ]; then \
		echo "Cognitive complexity over 15:"; \
		echo "$$output"; \
		exit 1; \
	fi

## test: Run tests
test:
	go test -count=1 ./...

## test-report: Run tests with coverage and JUnit reports (for CI)
test-report:
	@mkdir -p $(REPORTS_DIR)
	gotestsum --junitfile $(REPORTS_DIR)/junit.xml -- -count=1 -coverprofile=$(REPORTS_DIR)/coverage.out -covermode=count ./...
	@go tool cover -html=$(REPORTS_DIR)/coverage.out -o $(REPORTS_DIR)/coverage.html
	gocover-cobertura < $(REPORTS_DIR)/coverage.out > $(REPORTS_DIR)/coverage.xml

## check: Run all quality gates
check: fmt vet shadow lint vuln gosec gitleaks cyclomatic cognitive test

## install: Build and install to local bin
install: build
	@mkdir -p $(PREFIX)
	cp build/$(BINARY) $(PREFIX)/$(BINARY)
	@echo "installed $(PREFIX)/$(BINARY) ($(VERSION))"

## clean: Remove build artifacts
clean:
	rm -rf build/ dist/ $(REPORTS_DIR)

## release: Cross-compile for distribution
release: clean
	@mkdir -p dist
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)_darwin_arm64 .
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)_darwin_amd64 .
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)_linux_arm64 .
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)_linux_amd64 .
	@echo "Binaries in dist/"
	@ls -lh dist/

## version: Print current version
version:
	@echo $(VERSION)

## tag: Create a new version tag (usage: make tag v=0.1.0)
tag:
	@test -n "$(v)" || (echo "usage: make tag v=0.1.0" && exit 1)
	git tag -a -s v$(v) -m "Release v$(v)"
	@echo "tagged v$(v). Push with: git push origin v$(v)"
