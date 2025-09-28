# vault-dm-crypt

A Go implementation of [vaultlocker](https://github.com/openstack-charmers/vaultlocker) - a utility to store and
retrieve dm-crypt encryption keys in HashiCorp Vault.

## Overview

vault-dm-crypt provides the same functionality as the Python-based vaultlocker but is implemented in Go for better
performance, reduced dependencies, and improved maintainability. It enables secure management of encrypted block devices
using dm-crypt/LUKS with encryption keys stored in HashiCorp Vault.

## Features

- ✅ Encrypt block devices using LUKS/dm-crypt
- ✅ Store encryption keys securely in HashiCorp Vault
- ✅ Automatic device decryption on boot via systemd
- ✅ AppRole authentication for Vault access
- ✅ **Automatic secret ID refresh** with systemd timer
- ✅ **Intelligent secret ID lifecycle management**
- ✅ Retry mechanism for Vault connectivity
- ✅ Zero Python dependencies
- ✅ Compatible with modern Linux distributions

## Project Status

✅ **Production Ready** - Complete implementation with all core features

### Core Features Implemented

- ✅ Project structure and build system
- ✅ Makefile with comprehensive targets
- ✅ GitHub Actions CI/CD pipeline
- ✅ CLI framework with commands (encrypt/decrypt/refresh-auth)
- ✅ Comprehensive logging infrastructure
- ✅ Configuration module with TOML support
- ✅ Vault client integration with AppRole authentication
- ✅ Secret ID lifecycle management and automatic refresh
- ✅ SystemD integration for automated operations
- ✅ Security hardening and proper error handling

## Requirements

- Linux kernel 3.18+ (dm-crypt support)
- cryptsetup 2.0+
- systemd 230+
- Go 1.25+ (for building)
- Root privileges (for dm-crypt operations)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/axonops/vault-dm-crypt.git
cd vault-dm-crypt

# Build the binary
make build

# Install (requires sudo)
make install
```

## Usage

### Encrypt a block device

```bash
vault-dm-crypt encrypt /dev/sdd1
```

### Decrypt a device

```bash
vault-dm-crypt decrypt <uuid>
```

### Authentication Management

Manage AppRole secret ID lifecycle:

```bash
# Check authentication status
vault-dm-crypt refresh-auth --status

# Refresh secret ID if expiring within 60 minutes
vault-dm-crypt refresh-auth --refresh-if-expiring --update-config

# Always generate new secret ID
vault-dm-crypt refresh-auth --refresh-secret-id --update-config
```

### Automated Secret ID Refresh

For production environments, use the included systemd timer to automatically refresh secret IDs:

```bash
# Install systemd units
sudo cp configs/systemd/vault-dm-crypt-refresh.service /etc/systemd/system/
sudo cp configs/systemd/vault-dm-crypt-refresh.timer /etc/systemd/system/
sudo systemctl daemon-reload

# Enable automatic refresh every 15 minutes
sudo systemctl enable vault-dm-crypt-refresh.timer
sudo systemctl start vault-dm-crypt-refresh.timer

# Monitor refresh activity
sudo journalctl -u vault-dm-crypt-refresh.service -f
```

### Configuration

Configuration file is located at `/etc/vault-dm-crypt/config.toml`:

```toml
[vault]
url = "https://vault.example.com:8200"
backend = "secret"
approle = "your-approle-id"
secret_id = "your-secret-id"
approle_name = "vault-dm-crypt"  # Required for secret ID refresh
ca_bundle = "/etc/ssl/certs/ca-certificates.crt"
timeout = 30
retry_max = 3
retry_delay = 5

[logging]
level = "info"
format = "json"
output = "/var/log/vault-dm-crypt.log"
```

## Development

See [CLAUDE.md](CLAUDE.md) for development commands and guidelines.

### Quick Start

```bash
# Download dependencies
make deps

# Run tests
make test

# Build development version
make dev

# Run with verbose output
./build/vault-dm-crypt --verbose encrypt /dev/sdd1
```

## Migration from vaultlocker

This project maintains compatibility with the existing vaultlocker:

- Same Vault paths: `secret/vaultlocker/<uuid>`
- Same systemd service pattern (renamed to vault-dm-crypt)
- Same CLI commands: encrypt/decrypt

## License

Apache License 2.0 (same as original vaultlocker)

## Contributing

Contributions are welcome! Please see the [implementation plan](plans/PLAN.md) for current development priorities.
