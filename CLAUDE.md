# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This project is a clone of vaultlocker (https://github.com/openstack-charmers/vaultlocker) which provides the same
functionality but is implemented in Go rather than Python. The existing vaultlocker project is not maintained and is
not compatible with recent versions of Python, so the aim of this project is to create a clone with the same
functionality but without the dependencies.

This will be used in a production environment to mount encrypted volumes on Linux hosts using dm-crypt. The encryption
keys for dm-crypt will be stored in Hashicorp Vault and retrieved by the vault-dm-crypt service during startup to mount
the volumes.

## Development Commands

### Go Module Management

```bash
# Download dependencies
go mod download

# Add missing and remove unused modules
go mod tidy

# Verify dependencies
go mod verify
```

### Building

```bash
# Build the project using Makefile
make build

# Build with race detection (for development)
make race

# Build development version with debug symbols
make dev

# Cross-compile for different architectures
make build-all

# Build the project directly with go
go build -o vault-dm-crypt ./cmd/vault-dm-crypt

# Build with race detection (for development)
go build -race -o vault-dm-crypt ./cmd/vault-dm-crypt
```

### Testing

```bash
# Run all tests using Makefile
make test

# Run tests with verbose output
make test-verbose

# Run tests with coverage
make test-cover

# Run specific test
TEST=TestName make test-run

# Run all tests directly with go
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Run a specific test
go test -run TestName ./...
```

### Linting and Formatting

```bash
# Format code using Makefile
make fmt

# Run go vet using Makefile
make vet

# Run linting (includes golangci-lint if installed)
make lint

# Format code directly
go fmt ./...

# Run go vet for static analysis
go vet ./...

# Install and run golangci-lint (if available)
golangci-lint run
```

### Installation

```bash
# Install binary and systemd service (requires sudo)
make install

# Uninstall
make uninstall
```

### Makefile Targets

```bash
# Display all available targets
make help

# Clean build artifacts
make clean

# Download and verify dependencies
make deps
```

## Key Development Notes

- This project uses Go 1.25 as specified in go.mod
- Module path: `axonops/vault-dm-crypt`
- When implementing Vault integration, use the official HashiCorp Vault Go client library
- For dm-crypt operations root access will be required, so the whole project should be run as root
