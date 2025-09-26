# Integration Test Framework

This directory contains the integration test framework for vault-dm-crypt. The framework provides comprehensive end-to-end testing capabilities including Docker-based Vault servers, loop device testing for dm-crypt operations, and full workflow validation.

## Overview

The integration test framework is designed to test the complete vault-dm-crypt functionality in an isolated environment that closely mimics production conditions. It includes:

- **Docker-based Vault server**: Automatically starts and configures a Vault container for testing
- **Loop device management**: Creates and manages loop devices for safe dm-crypt testing
- **End-to-end workflows**: Tests complete encrypt/decrypt cycles
- **Error condition testing**: Validates proper error handling and edge cases
- **CLI interface testing**: Verifies command-line argument parsing and validation
- **Concurrent operation testing**: Tests system behavior under concurrent operations

## Prerequisites

### System Requirements

- **Linux system**: Required for dm-crypt operations
- **Root privileges**: Required for dm-crypt and loop device operations
- **Docker**: Required for Vault container management
- **Go 1.21+**: Required for building and running tests

### Required Commands

The following commands must be available in the system PATH:

- `docker` - For Vault container management
- `vault` - HashiCorp Vault CLI (for Vault configuration)
- `curl` - For health checks and HTTP operations
- `losetup` - For loop device management
- `dd` - For creating test images
- `cryptsetup` - For LUKS operations (when testing as root)
- `systemctl` - For systemd integration tests (optional)

### Installation

Install required system packages on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y docker.io vault curl util-linux cryptsetup-bin
```

Install required system packages on RHEL/CentOS/Fedora:

```bash
sudo dnf install -y docker vault curl util-linux cryptsetup
sudo systemctl start docker
```

## Running Tests

### Basic Test Execution

Run all integration tests:

```bash
cd test/integration
go test -v ./...
```

### Running Specific Test Categories

Run only Vault integration tests:

```bash
go test -v -run TestVaultIntegration
```

Run only CLI interface tests:

```bash
go test -v -run TestCommandLineInterface
```

Run only error handling tests:

```bash
go test -v -run TestErrorHandling
```

### Running Tests with Root Privileges

Some tests require root privileges for dm-crypt operations:

```bash
sudo -E go test -v -run TestEndToEndEncryptDecrypt
```

The `-E` flag preserves environment variables needed for Go module resolution.

### Test Output and Debugging

For verbose output with debug logging:

```bash
go test -v -args -debug
```

To see Docker container logs during tests:

```bash
DOCKER_DEBUG=1 go test -v
```

## Test Categories

### 1. Vault Integration Tests (`TestVaultIntegration`)

Tests basic Vault connectivity and authentication:

- Vault server startup and configuration
- AppRole authentication
- Secret storage and retrieval
- Configuration file validation

**Requirements**: Docker, Vault CLI

### 2. End-to-End Tests (`TestEndToEndEncryptDecrypt`)

Tests complete encrypt/decrypt workflows:

- Loop device creation and management
- Device encryption with LUKS
- Key storage in Vault
- Device decryption and mapping
- Cleanup operations

**Requirements**: Root privileges, Docker, Vault CLI, cryptsetup

### 3. Error Handling Tests (`TestErrorHandling`)

Tests various error conditions:

- Invalid device paths
- Non-existent UUIDs
- Invalid configuration files
- Authentication failures
- Permission errors

**Requirements**: Docker, Vault CLI

### 4. CLI Interface Tests (`TestCommandLineInterface`)

Tests command-line interface:

- Help and version commands
- Argument parsing and validation
- Error messages and exit codes
- Flag handling

**Requirements**: None (uses built binary only)

### 5. Systemd Integration Tests (`TestSystemdIntegration`)

Tests systemd service management:

- Service template validation
- Service installation (when root)
- Service status checking

**Requirements**: systemd, systemctl

### 6. Concurrent Operations Tests (`TestConcurrentOperations`)

Tests system behavior under load:

- Multiple simultaneous operations
- Resource contention handling
- Error isolation

**Requirements**: Docker, Vault CLI

## Framework Architecture

### Core Components

#### `TestFramework` struct

The main framework class that provides:

- Docker container management
- Vault server lifecycle
- Loop device creation/cleanup
- Configuration file generation
- Binary building and execution

#### Key Methods

- `Setup()`: Initializes the complete test environment
- `Cleanup()`: Tears down all resources
- `CreateLoopDevice(sizeMB)`: Creates a loop device for testing
- `GetVaultConfig()`: Returns Vault connection details
- `RunCommand(args...)`: Executes the vault-dm-crypt binary
- `RequireRoot()`: Skips tests that need root privileges
- `RequireDocker()`: Skips tests when Docker is unavailable

### Test Lifecycle

1. **Setup Phase**:
   - Build vault-dm-crypt binary
   - Initialize Docker client
   - Start Vault container
   - Configure Vault with test policies and roles
   - Create temporary directories

2. **Test Execution**:
   - Create test-specific resources (loop devices, config files)
   - Execute vault-dm-crypt commands
   - Validate outputs and behavior

3. **Cleanup Phase**:
   - Remove loop devices
   - Stop Vault container
   - Clean up temporary files
   - Close Docker connections

## Configuration

### Vault Configuration

The framework automatically configures Vault with:

- AppRole authentication method
- Test policy with appropriate permissions
- KV v2 secrets engine at `secret/`
- Test role with 1-hour token TTL

### Test Configuration Files

Generated configuration files include:

```toml
[vault]
url = "http://127.0.0.1:RANDOM_PORT"
backend = "secret"
approle = "GENERATED_ROLE_ID"
secret_id = "GENERATED_SECRET_ID"
timeout = 30
retry_max = 3
retry_delay = 5

[logging]
level = "debug"
format = "text"
output = "stdout"
```

## Security Considerations

### Test Isolation

- Each test run uses a fresh Vault container
- Temporary directories are unique per test
- Loop devices are automatically cleaned up
- No persistent state between test runs

### Privilege Requirements

- Root privileges are only required for actual dm-crypt operations
- Most tests run without root and skip dm-crypt operations
- Framework automatically detects and adapts to privilege level

### Data Safety

- All operations use loop devices, never real block devices
- Test data is limited to temporary directories
- No system configuration is modified
- Vault containers are ephemeral and destroyed after tests

## Troubleshooting

### Common Issues

#### Docker Permission Errors

```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Re-login or use newgrp docker
```

#### Vault Container Startup Failures

```bash
# Check Docker daemon status
sudo systemctl status docker
# Check available ports
ss -tlnp | grep :8200
```

#### Loop Device Creation Failures

```bash
# Check available loop devices
losetup -f
# Check permissions
ls -la /dev/loop*
```

#### Module Resolution Issues

```bash
# Ensure Go modules are properly initialized
cd test/integration
go mod download
go mod tidy
```

### Debug Mode

Enable debug logging by setting environment variables:

```bash
export VAULT_DM_CRYPT_DEBUG=1
export DOCKER_API_VERSION=1.41
go test -v
```

### Log Collection

Collect logs from failed tests:

```bash
go test -v 2>&1 | tee integration-test.log
```

## Contributing

When adding new integration tests:

1. Use the `TestFramework` for consistent setup/cleanup
2. Add appropriate requirement checks (`RequireRoot()`, `RequireDocker()`, etc.)
3. Use descriptive test names and error messages
4. Document any new system requirements
5. Ensure tests clean up properly even on failure
6. Add tests to the appropriate category or create new categories as needed

### Adding New Test Categories

1. Create a new test function following the naming convention `TestCategoryName`
2. Document the test category in this README
3. Add appropriate requirement checks
4. Include the test in CI/CD pipelines
5. Update the test matrix in documentation

## Continuous Integration

The integration tests can be run in CI/CD environments with:

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y docker.io vault curl util-linux cryptsetup-bin

# Run tests (subset that doesn't require root)
go test -v -run "TestVaultIntegration|TestCommandLineInterface|TestErrorHandling"

# Run tests with root (in privileged containers)
sudo -E go test -v
```

For GitHub Actions or similar CI systems, ensure the runner has:

- Docker service enabled
- Privileged container access (for dm-crypt tests)
- Appropriate system packages installed