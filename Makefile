# Project settings
BINARY_NAME=road-1337
MODULE=github.com/ValeryCherneykin/road-1337
BIN_DIR=bin

# Tools
GOLANGCI_LINT=$(BIN_DIR)/golangci-lint
GOFUMPT=$(BIN_DIR)/gofumpt
GCI=$(BIN_DIR)/gci

.PHONY: all fmt lint test vet clean build install-tools

all: check

# Install tools locally
install-tools:
	@mkdir -p $(BIN_DIR)
	@echo "Installing tools..."
	@GOBIN=$(abspath $(BIN_DIR)) go install mvdan.cc/gofumpt@latest
	@GOBIN=$(abspath $(BIN_DIR)) go install github.com/daixiang0/gci@latest
	@GOBIN=$(abspath $(BIN_DIR)) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

# Code formatting
fmt: install-tools
	@echo "Formatting code..."
	@$(GOFUMPT) -l -w .
	@$(GCI) write --skip-generated -s standard -s default -s "prefix($(MODULE))" .

# Linting
lint: install-tools
	@echo "Running linter..."
	@$(GOLANGCI_LINT) run ./...

# Testing
test:
	@echo "Running tests..."
	@go test -v -count=1 ./...

test-race:
	@echo "Running tests with race detector..."
	@go test -v -race -count=1 ./...

# Static analysis
vet:
	@echo "Running go vet..."
	@go vet ./...

# Full check pipeline
check: fmt vet lint test
	@echo "✅ All checks passed!"

# Clean up
clean:
	@echo "Cleaning up..."
	@rm -rf $(BIN_DIR)
	@go clean -cache -testcache

# Git tagging
tag:
	@if [ -z "$(v)" ]; then echo "Usage: make tag v=v1.0.0"; exit 1; fi
	git tag -a $(v) -m "Release $(v)"
	@echo "✅ Tag $(v) created. Push with: git push origin $(v)"
