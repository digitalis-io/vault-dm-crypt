# Vault-DM-Crypt Go Implementation Plan

## Executive Summary

This document outlines the complete implementation plan for porting the Python-based vaultlocker to Go. The new
implementation will maintain full compatibility with the existing vaultlocker functionality while providing better
performance, reduced dependencies, and improved maintainability.

## Project Overview

### Original Project Analysis

- **Name**: vaultlocker
- **Purpose**: Store and retrieve dm-crypt encryption keys in HashiCorp Vault
- **Key Features**:
    - Encrypts block devices using LUKS/dm-crypt
    - Stores encryption keys securely in HashiCorp Vault
    - Automatic device decryption on boot via systemd
    - AppRole authentication for Vault access
    - Retry mechanism for Vault connectivity

### Go Implementation Goals

- Feature parity with Python vaultlocker
- Zero Python dependencies
- Improved error handling and logging
- Better performance for system operations
- Maintainable, idiomatic Go code
- Compatible with modern Linux distributions

## Architecture Design

### Package Structure

```
vault-dm-crypt/
├── main.go                      # CLI entry point
├── internal/
│   ├── config/
│   │   ├── config.go            # Configuration parsing
│   │   └── config_test.go
│   ├── vault/
│   │   ├── client.go            # Vault client wrapper
│   │   ├── auth.go              # AppRole authentication
│   │   └── vault_test.go
│   ├── dmcrypt/
│   │   ├── dmcrypt.go           # dm-crypt operations
│   │   ├── luks.go              # LUKS formatting/opening
│   │   └── dmcrypt_test.go
│   ├── systemd/
│   │   ├── systemd.go           # systemd integration
│   │   └── systemd_test.go
│   └── shell/
│   │   ├── executor.go          # Command execution wrapper
│   │   └── executor_test.go
│   └── errors/
│       └── errors.go            # Custom error types
├── config/
│   ├── vaultlocker.conf         # Default configuration
│   └── systemd/
│       └── vault-dm-crypt-decrypt@.service
├── docs/
│   ├── API.md
│   ├── CONFIGURATION.md
│   └── USAGE.md
├── test/
│   ├── integration/
│   └── fixtures/
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## Implementation Phases

### Phase 1: Core Foundation (Week 1)

1. **Project Setup**
    - Initialize Go module structure
    - Set up Makefile with build, test, install targets
    - Configure CI/CD pipeline (GitHub Actions)
    - Set up dependency management (go.mod)

2. **Configuration Module**
    - Implement configuration file parser (TOML/YAML)
    - Support environment variable overrides
    - Validate configuration parameters
    - Default configuration handling

3. **Error Handling Framework**
    - Define custom error types matching Python exceptions:
        - VaultlockerError (base)
        - VaultWriteError
        - VaultReadError
        - VaultDeleteError
        - VaultKeyMismatch
        - LUKSFailure
    - Implement error wrapping and context

### Phase 2: Vault Integration (Week 1-2)

1. **Vault Client Implementation**
    - Use official HashiCorp Vault Go client
    - Implement connection pooling and retry logic
    - TLS/CA certificate bundle support
    - Connection timeout handling

2. **AppRole Authentication**
    - Implement AppRole authentication flow
    - Token renewal mechanism
    - Secret ID rotation support
    - Error recovery and re-authentication

3. **Secret Management**
    - Write encryption keys to Vault
    - Read encryption keys from Vault
    - Delete keys when needed
    - Support multiple backend types

### Phase 3: DM-Crypt Operations (Week 2)

1. **Key Generation**
    - Generate 4096-bit random keys
    - Base64 encoding/decoding
    - Key validation

2. **LUKS Operations**
    - Format devices with LUKS
    - Open encrypted devices
    - UUID management
    - Device mapper naming

3. **System Integration**
    - udev integration for device discovery
    - Device rescan and settle operations
    - Block device validation
    - Permission checks (root requirement)

### Phase 4: CLI Implementation (Week 3)

1. **Command Structure**
    - Use cobra/urfave CLI framework
    - Main commands:
        - `encrypt <device>` - Encrypt a block device
        - `decrypt <uuid>` - Decrypt and open a device
    - Global flags:
        - `--config` - Configuration file path
        - `--retry` - Retry timeout in seconds
        - `--verbose` - Verbose output
        - `--debug` - Debug logging

2. **Command Implementation**
    - Encrypt command workflow:
      ```
      1. Validate device exists and is unmounted
      2. Generate encryption key
      3. Store key in Vault at path: secret/vaultlocker/<uuid>
      4. Format device with LUKS using key
      5. Open LUKS device
      6. Enable systemd service for auto-mount
      7. Output mapped device path
      ```

    - Decrypt command workflow:
      ```
      1. Retrieve key from Vault using UUID
      2. Open LUKS device with key
      3. Output mapped device path
      ```

3. **Logging and Output**
    - Structured logging (logrus)
    - JSON output option for automation
    - Progress indicators for long operations
    - Clear error messages

### Phase 5: SystemD Integration (Week 3)

1. **Service Files**
    - Create vault-dm-crypt-decrypt@.service template
    - Support instance parameters (%i for UUID)
    - Dependency management (After=network-online.target)
    - Timeout configuration

2. **Service Management**
    - Enable/disable service instances
    - Status checking
    - Journal integration for logging

### Phase 6: Testing & Documentation (Week 4)

1. **Unit Tests**
    - Minimum 80% code coverage
    - Mock Vault interactions
    - Mock system commands
    - Test error conditions

2. **Integration Tests**
    - Docker-based test environment
    - Real Vault server testing
    - Loop device testing for dm-crypt
    - End-to-end encryption/decryption

3. **Documentation**
    - Installation guide
    - Configuration reference
    - Usage examples
    - Migration guide from Python vaultlocker
    - API documentation (godoc)

### Phase 7: Deployment & Migration (Week 4)

1. **Build & Packaging**
    - Static binary compilation
    - Cross-compilation support (amd64, arm64)
    - Debian/RPM package creation

2. **Migration Tools**
    - Configuration converter (Python format → Go format)
    - Vault path migration utility
    - Compatibility validation tool

## Technical Specifications

### Dependencies

IMPORTANT: Note that newer versions of these dependencies could have been released since this document was created.
Always ensure that the latest versions are used.

```go
// go.mod dependencies
github.com/hashicorp/vault/api v1.9.0
github.com/spf13/cobra v1.7.0
github.com/spf13/viper v1.16.0
github.com/sirupsen/logrus v1.9.3
github.com/stretchr/testify v1.8.4
```

### System Requirements

- Linux kernel 3.18+ (dm-crypt support)
- cryptsetup 2.0+
- systemd 230+
- Go 1.25+ (for building)
- Root privileges (for dm-crypt operations)

### Configuration File Format

```toml
# /etc/vault-dm-crypt/config.toml
[vault]
url = "http://10.5.0.13:8200"
backend = "secret"
approle = "e256bf3b-fb28-b1d6-f2fb-3adc8339d3ad"
secret_id = "9428ad25-7b4a-442f-8f20-f23be0575146"
ca_bundle = "/etc/ssl/certs/ca-certificates.crt"
timeout = 30
retry_max = 3
retry_delay = 5

[logging]
level = "info"
format = "json"
output = "/var/log/vault-dm-crypt.log"
```

### Vault Secret Schema

```json
{
  "path": "secret/vaultlocker/<device-uuid>",
  "data": {
    "dmcrypt_key": "<base64-encoded-key>",
    "created_at": "2024-01-15T10:30:00Z",
    "device": "/dev/sdd1",
    "hostname": "server01"
  }
}
```

## Security Considerations

1. **Key Management**
    - Keys never written to disk
    - Memory scrubbing after use
    - Secure random generation using crypto/rand

2. **Vault Communication**
    - TLS enforcement for production
    - Certificate validation
    - Token expiration handling

3. **System Security**
    - Root privilege requirement validation
    - Device permission checks
    - Audit logging for all operations

4. **Error Handling**
    - No sensitive data in error messages
    - Proper cleanup on failure
    - Atomic operations where possible

## Performance Targets

- Vault connection: < 500ms
- Key generation: < 100ms
- Device encryption (1GB): < 30s
- Device decryption: < 2s
- Memory usage: < 50MB
- Binary size: < 15MB

## Compatibility Matrix

| Component       | Python vaultlocker          | Go vault-dm-crypt         |
|-----------------|-----------------------------|---------------------------|
| Vault paths     | ✓ secret/vaultlocker/<uuid> | ✓ Same                    |
| Config format   | INI                         | TOML (with converter)     |
| SystemD service | ✓ vaultlocker-decrypt@      | ✓ vault-dm-crypt-decrypt@ |
| CLI commands    | encrypt/decrypt             | encrypt/decrypt           |
| LUKS format     | LUKS1/2                     | LUKS1/2                   |
| AppRole auth    | ✓                           | ✓                         |

## Risk Mitigation

1. **Data Loss Prevention**
    - Confirmation prompts for destructive operations
    - Backup key generation option
    - Recovery key support

2. **Compatibility Issues**
    - Extensive testing on multiple distributions
    - Version detection for system tools
    - Graceful degradation

3. **Migration Risks**
    - Parallel installation support
    - Rollback procedures
    - Data validation tools

## Success Criteria

- [ ] Feature parity with Python vaultlocker
- [ ] All unit tests passing (>80% coverage)
- [ ] Integration tests passing
- [ ] Performance targets met
- [ ] Documentation complete
- [ ] Successfully encrypts/decrypts test devices
- [ ] SystemD service working on boot
- [ ] No Python dependencies
- [ ] Binary size under 15MB
- [ ] Memory usage under 50MB
- [ ] Compatible with Ubuntu 20.04+, RHEL 8+, Debian 11+

## Timeline Summary

- **Week 1**: Core foundation + Vault integration start
- **Week 2**: Complete Vault integration + DM-Crypt operations
- **Week 3**: CLI implementation + SystemD integration
- **Week 4**: Testing, documentation, and deployment preparation

Total estimated time: 4 weeks for full implementation

## Implementation Status

### ✅ Completed (Phases 1-5)

**Phase 1: Core Foundation** ✅
- [x] Project Setup: Go module, Makefile, CI/CD pipeline, dependencies
- [x] Configuration Module: TOML parser, environment overrides, validation
- [x] Error Handling Framework: Custom error types with wrapping and context

**Phase 2: Vault Integration** ✅
- [x] Vault Client Implementation: Official HashiCorp client, retry logic, TLS support
- [x] AppRole Authentication: Token renewal, secret rotation, error recovery
- [x] Secret Management: Read/write/delete operations, multiple backend support

**Phase 3: DM-Crypt Operations** ✅
- [x] Key Generation: 4096-bit cryptographically secure keys with validation
- [x] LUKS Operations: Device formatting, opening, UUID management, device mapping
- [x] System Integration: udev integration, device validation, permission checks

**Phase 4: CLI Implementation** ✅
- [x] Command Structure: Cobra framework with encrypt/decrypt commands
- [x] Full Command Implementation: Complete encrypt/decrypt workflows
- [x] Logging and Output: Structured logging with logrus, clear error messages

**Phase 5: SystemD Integration** ✅
- [x] Service Files: vault-dm-crypt-decrypt@.service template with dependencies
- [x] Service Management: Enable/disable, status checking, journal integration
- [x] Boot Integration: Automatic decryption on system startup

## Next Steps

### 🔄 Phase 6: Testing & Documentation (In Progress)

**Unit Testing Improvements**
- [ ] **Increase dmcrypt test coverage** from 34.2% to >80% target
- [ ] **Increase vault test coverage** from 35.2% to >80% target
- [ ] **Add CLI command tests** (currently 0% coverage)
- [ ] **Mock system command interactions** for more isolated testing
- [ ] **Add edge case and error condition testing**

**Integration Testing**
- [ ] **Docker-based test environment** for end-to-end testing
- [ ] **Real Vault server integration tests** with temporary Vault instances
- [ ] **Loop device testing** for actual dm-crypt operations without requiring real block devices
- [ ] **End-to-end encryption/decryption workflow tests**
- [ ] **SystemD service testing** in containerized environment

**Documentation Creation**
- [ ] **Installation guide** with system requirements and dependencies
- [ ] **Configuration reference** with all available options and examples
- [ ] **Usage examples** and common workflows
- [ ] **Migration guide** from Python vaultlocker with compatibility notes
- [ ] **API documentation** using godoc for all public interfaces
- [ ] **Troubleshooting guide** with common issues and solutions

### 🔄 Phase 7: Deployment & Migration

**Build & Packaging**
- [ ] **Static binary compilation** for distribution without dependencies
- [ ] **Cross-compilation support** for amd64, arm64 architectures
- [ ] **Debian package creation** (.deb) for Debian/Ubuntu distributions
- [ ] **RPM package creation** (.rpm) for RHEL/CentOS/Fedora distributions
- [ ] **Release automation** with GitHub Actions for tagged releases

**Migration Tools**
- [ ] **Configuration converter** to migrate from Python vaultlocker INI format to TOML
- [ ] **Vault path migration utility** to ensure compatibility with existing secrets
- [ ] **Compatibility validation tool** to verify successful migration
- [ ] **Parallel installation support** to run alongside Python version during migration

### 🆕 Additional Features & Enhancements

**Security Enhancements**
- [ ] **Recovery key support** for emergency access without Vault
- [ ] **Key rotation functionality** for existing encrypted devices
- [ ] **Audit logging** with detailed operation tracking
- [ ] **Multi-factor authentication** support for Vault access

**Operational Features**
- [ ] **Device listing command** to show all encrypted devices managed by vault-dm-crypt
- [ ] **Status checking command** for encrypted device health monitoring
- [ ] **Backup/restore functionality** for Vault keys
- [ ] **Batch operations** for managing multiple devices

**Advanced Integration**
- [ ] **Kubernetes operator** for cloud-native environments
- [ ] **Prometheus metrics** for monitoring and alerting
- [ ] **Vault namespace support** for multi-tenant deployments
- [ ] **Custom KMS integration** beyond Vault (AWS KMS, Azure Key Vault, etc.)

## Immediate Priorities

1. **Complete Phase 6 Testing** - Increase test coverage to meet 80% target
2. **Create Essential Documentation** - Installation guide, usage examples, configuration reference
3. **Integration Testing** - Docker-based end-to-end testing environment
4. **Build Packaging** - Create distributable packages for major Linux distributions
5. **Migration Tools** - Enable smooth transition from Python vaultlocker

## Success Criteria Update

### ✅ Completed
- [x] Feature parity with Python vaultlocker (core functionality)
- [x] CLI framework with encrypt/decrypt commands
- [x] SystemD service working with boot integration
- [x] No Python dependencies
- [x] Binary compilation successful

### 🔄 In Progress
- [ ] All unit tests passing (>80% coverage) - Currently: config 88.9%, shell 98.2%, systemd 70.2%, errors 100%, dmcrypt 34.2%, vault 35.2%
- [ ] Integration tests implemented and passing
- [ ] Performance targets validation
- [ ] Documentation complete
- [ ] Cross-platform compatibility testing (Ubuntu 20.04+, RHEL 8+, Debian 11+)

### 📋 Pending
- [ ] Memory usage validation (target <50MB)
- [ ] Performance benchmarking against targets
- [ ] Production deployment validation

