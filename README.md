# vault-dm-crypt

A Go implementation of [vaultlocker](https://github.com/openstack-charmers/vaultlocker) - a utility to store and retrieve dm-crypt encryption keys in HashiCorp Vault.

## Overview

vault-dm-crypt provides the same functionality as the Python-based vaultlocker but is implemented in Go for better performance, reduced dependencies, and improved maintainability. It enables secure management of encrypted block devices using dm-crypt/LUKS with encryption keys stored in HashiCorp Vault.

## Features

- ✅ Encrypt block devices using LUKS/dm-crypt
- ✅ Store encryption keys securely in HashiCorp Vault
- ✅ Automatic device decryption on boot via systemd
- ✅ AppRole authentication for Vault access
- ✅ Retry mechanism for Vault connectivity
- ✅ Zero Python dependencies
- ✅ Compatible with modern Linux distributions

## Project Status

🚧 **Under Development** - Following the implementation plan in [plans/PLAN.md](plans/PLAN.md)

### Completed
- ✅ Project structure and build system
- ✅ Makefile with comprehensive targets
- ✅ GitHub Actions CI/CD pipeline
- ✅ CLI framework with commands (encrypt/decrypt)
- ✅ Basic logging infrastructure

### In Progress
- 🔄 Configuration module
- 🔄 Vault client integration
- 🔄 DM-Crypt operations
- 🔄 SystemD integration

## Requirements

- Linux kernel 3.18+ (dm-crypt support)
- cryptsetup 2.0+
- systemd 230+
- Go 1.21+ (for building)
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

### Configuration

Configuration file is located at `/etc/vault-dm-crypt/config.toml`:

```toml
[vault]
url = "http://vault.example.com:8200"
backend = "secret"
approle = "your-approle-id"
secret_id = "your-secret-id"
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