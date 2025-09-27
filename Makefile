# Makefile for vault-dm-crypt

# Variables
BINARY_NAME := vault-dm-crypt
BINARY_PATH := ./cmd/vault-dm-crypt
BUILD_DIR := ./build
INSTALL_DIR := /usr/local/bin
SYSTEMD_DIR := /etc/systemd/system
CONFIG_DIR := /etc/vault-dm-crypt
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"
GOFLAGS := -v

# Go commands
GOCMD := $(shell which go)
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOVET := $(GOCMD) vet
GOFMT := gofmt
GOMOD := $(GOCMD) mod

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m # No Color

.PHONY: all build clean test test-verbose test-cover test-integration test-integration-root fmt vet lint install uninstall help deps dev race deb

# Default target
all: deps fmt vet test build

# Display help
help:
	@echo "$(GREEN)Available targets:$(NC)"
	@echo "  $(YELLOW)build$(NC)        - Build the binary"
	@echo "  $(YELLOW)clean$(NC)        - Remove build artifacts"
	@echo "  $(YELLOW)test$(NC)         - Run unit tests"
	@echo "  $(YELLOW)test-verbose$(NC) - Run unit tests with verbose output"
	@echo "  $(YELLOW)test-cover$(NC)   - Run unit tests with coverage"
	@echo "  $(YELLOW)test-integration$(NC) - Run integration tests"
	@echo "  $(YELLOW)test-integration-root$(NC) - Run integration tests with root privileges"
	@echo "  $(YELLOW)fmt$(NC)          - Format code"
	@echo "  $(YELLOW)vet$(NC)          - Run go vet"
	@echo "  $(YELLOW)lint$(NC)         - Run golangci-lint (if installed)"
	@echo "  $(YELLOW)install$(NC)      - Install binary and systemd service"
	@echo "  $(YELLOW)uninstall$(NC)    - Uninstall binary and systemd service"
	@echo "  $(YELLOW)deps$(NC)         - Download and verify dependencies"
	@echo "  $(YELLOW)dev$(NC)          - Build development version"
	@echo "  $(YELLOW)race$(NC)         - Build with race detector"
	@echo "  $(YELLOW)deb$(NC)          - Build Debian package"

# Download dependencies
deps:
	@echo "$(GREEN)Downloading dependencies...$(NC)"
	@$(GOMOD) download
	@$(GOMOD) verify
	@$(GOMOD) tidy

# Build the binary
build: deps
	@echo "$(GREEN)Building $(BINARY_NAME)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(BINARY_PATH)
	@echo "$(GREEN)Build complete: $(BUILD_DIR)/$(BINARY_NAME)$(NC)"

# Build development version (with debug symbols)
dev:
	@echo "$(GREEN)Building development version...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-dev $(BINARY_PATH)
	@echo "$(GREEN)Development build complete: $(BUILD_DIR)/$(BINARY_NAME)-dev$(NC)"

# Build with race detector
race:
	@echo "$(GREEN)Building with race detector...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@$(GOBUILD) -race -o $(BUILD_DIR)/$(BINARY_NAME)-race $(BINARY_PATH)
	@echo "$(GREEN)Race detector build complete: $(BUILD_DIR)/$(BINARY_NAME)-race$(NC)"

# Clean build artifacts
clean:
	@echo "$(GREEN)Cleaning build artifacts...$(NC)"
	@rm -rf $(BUILD_DIR)
	@$(GOCMD) clean
	@echo "$(GREEN)Clean complete$(NC)"

# Run unit tests
test:
	@echo "$(GREEN)Running unit tests...$(NC)"
	@$(GOTEST) ./...

# Run unit tests with verbose output
test-verbose:
	@echo "$(GREEN)Running unit tests (verbose)...$(NC)"
	@$(GOTEST) -v ./...

# Run unit tests with coverage
test-cover:
	@echo "$(GREEN)Running unit tests with coverage...$(NC)"
	@$(GOTEST) -cover -coverprofile=coverage.out ./...
	@$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(NC)"

# Run integration tests
test-integration: build
	@echo "$(GREEN)Running integration tests...$(NC)"
	@if command -v docker &> /dev/null; then \
		cd test/integration && $(GOTEST) -v -timeout=10m .; \
	else \
		echo "$(YELLOW)Docker not available, skipping integration tests$(NC)"; \
	fi

# Run integration tests with root privileges
#test-integration-root: build
#	@echo "$(GREEN)Running integration tests with root privileges...$(NC)"
#	@if [ "$(shell id -u)" = "0" ]; then \
#		if command -v docker &> /dev/null; then \
#			cd test/integration && $(GOTEST) -v -timeout=15m .; \
#		else \
#			echo "$(YELLOW)Docker not available, skipping integration tests$(NC)"; \
#		fi \
#	else \
#		echo "$(YELLOW)Root privileges required. Run: sudo make test-integration-root$(NC)"; \
#	fi

# Run integration tests with root privileges
test-integration-root: build
	@echo "$(GREEN)Running integration tests with root privileges...$(NC)"
	if command -v docker &> /dev/null; then \
		cd test/integration && sudo $(GOTEST) -v -timeout=15m .; \
	else \
		echo "$(YELLOW)Docker not available, skipping integration tests$(NC)"; \
	fi

# Run specific test
test-run:
	@echo "$(GREEN)Running specific test: $(TEST)$(NC)"
	@$(GOTEST) -v -run $(TEST) ./...

# Format code
fmt:
	@echo "$(GREEN)Formatting code...$(NC)"
	@$(GOFMT) -s -w .
	@$(GOCMD) fmt ./...

# Run go vet
vet:
	@echo "$(GREEN)Running go vet...$(NC)"
	@$(GOVET) ./...

# Run golangci-lint (if installed)
lint:
	@echo "$(GREEN)Running golangci-lint...$(NC)"
	@if command -v golangci-lint &> /dev/null; then \
		golangci-lint run; \
	else \
		echo "$(YELLOW)golangci-lint not installed. Install with:$(NC)"; \
		echo "curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin"; \
	fi

# Install binary and systemd service
install: build
	@echo "$(GREEN)Installing $(BINARY_NAME)...$(NC)"
	@sudo mkdir -p $(CONFIG_DIR)
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/
	@sudo chmod +x $(INSTALL_DIR)/$(BINARY_NAME)
	@if [ -f configs/vaultlocker.conf ]; then \
		sudo cp configs/vaultlocker.conf $(CONFIG_DIR)/config.toml; \
		echo "$(GREEN)Configuration file installed to $(CONFIG_DIR)/config.toml$(NC)"; \
	fi
	@if [ -f configs/systemd/vault-dm-crypt-decrypt@.service ]; then \
		sudo cp configs/systemd/vault-dm-crypt-decrypt@.service $(SYSTEMD_DIR)/; \
		sudo systemctl daemon-reload; \
		echo "$(GREEN)Systemd service installed$(NC)"; \
	fi
	@echo "$(GREEN)Installation complete$(NC)"

# Uninstall binary and systemd service
uninstall:
	@echo "$(RED)Uninstalling $(BINARY_NAME)...$(NC)"
	@sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@sudo rm -f $(SYSTEMD_DIR)/vault-dm-crypt-decrypt@.service
	@sudo systemctl daemon-reload
	@echo "$(RED)Uninstallation complete$(NC)"

# Cross-compilation targets
.PHONY: build-linux-amd64 build-linux-arm64 build-all

build-linux-amd64:
	@echo "$(GREEN)Building for linux/amd64...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(BINARY_PATH)

build-linux-arm64:
	@echo "$(GREEN)Building for linux/arm64...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(BINARY_PATH)

build-all: build-linux-amd64 build-linux-arm64
	@echo "$(GREEN)All cross-compilation builds complete$(NC)"

# Build Debian package
deb: clean
	@echo "$(GREEN)Building Debian package...$(NC)"
	@if ! command -v dpkg-buildpackage &> /dev/null; then \
		echo "$(RED)Error: dpkg-buildpackage not found. Install with:$(NC)"; \
		echo "sudo apt-get install dpkg-dev build-essential"; \
		exit 1; \
	fi
	@if ! command -v debhelper &> /dev/null; then \
		echo "$(RED)Error: debhelper not found. Install with:$(NC)"; \
		echo "sudo apt-get install debhelper"; \
		exit 1; \
	fi
	@echo "$(GREEN)Building package with dpkg-buildpackage...$(NC)"
	@dpkg-buildpackage -us -uc -b
	@echo "$(GREEN)Debian package build complete!$(NC)"
	@echo "$(GREEN)Package files created in parent directory:$(NC)"
	@ls -la ../vault-dm-crypt_*.deb 2>/dev/null || echo "$(YELLOW)No .deb files found in parent directory$(NC)"
