.PHONY: build test clean coverage lint help

# Default target
all: build

# Build the application
build:
	@echo "Building HTTP Request Reliability Tester..."
	go build -o http-tester .

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run security and quality checks
security:
	@echo "Running security checks..."
	gosec ./...
	@echo "Running vulnerability check..."
	@if [ -f "/Users/benvon/.asdf/installs/golang/1.24.4/bin/govulncheck" ]; then \
		/Users/benvon/.asdf/installs/golang/1.24.4/bin/govulncheck ./...; \
	elif [ -f "$(shell go env GOROOT)/bin/govulncheck" ]; then \
		$(shell go env GOROOT)/bin/govulncheck ./...; \
	elif [ -f "$(shell go env GOPATH)/bin/govulncheck" ]; then \
		$(shell go env GOPATH)/bin/govulncheck ./...; \
	elif command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not found, skipping vulnerability check"; \
	fi

# Run static analysis
staticcheck:
	@echo "Running static analysis..."
	@if [ -f "/Users/benvon/.asdf/installs/golang/1.24.4/bin/staticcheck" ]; then \
		/Users/benvon/.asdf/installs/golang/1.24.4/bin/staticcheck ./...; \
	elif [ -f "$(shell go env GOROOT)/bin/staticcheck" ]; then \
		$(shell go env GOROOT)/bin/staticcheck ./...; \
	elif [ -f "$(shell go env GOPATH)/bin/staticcheck" ]; then \
		$(shell go env GOPATH)/bin/staticcheck ./...; \
	elif command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not found, skipping static analysis"; \
	fi

# Run all quality checks
quality: test security staticcheck

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f http-tester
	rm -f coverage.out coverage.html

# Run linting
lint:
	@echo "Running linter..."
	golangci-lint run

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod download

# Run the application with default settings
run: build
	@echo "Running HTTP Request Reliability Tester..."
	./http-tester

# Run with custom settings (example)
run-example: build
	@echo "Running with example settings..."
	./http-tester --duration 1m --rate 30 --output json

# Install development tools
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest

# Show help
help:
	@echo "Available targets:"
	@echo "  build        - Build the application"
	@echo "  test         - Run tests"
	@echo "  security     - Run security checks (gosec, govulncheck)"
	@echo "  staticcheck  - Run static analysis"
	@echo "  quality      - Run all quality checks (test, security, staticcheck)"
	@echo "  coverage     - Run tests with coverage report"
	@echo "  clean        - Clean build artifacts"
	@echo "  lint         - Run linter"
	@echo "  deps         - Install dependencies"
	@echo "  run          - Run the application"
	@echo "  run-example  - Run with example settings"
	@echo "  install-tools - Install development tools"
	@echo "  help         - Show this help" 