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
- ✅ Vault authentication (AppRole and Token authentication)
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
- ✅ Vault client integration with AppRole and Token authentication
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
git clone https://github.com/digitalisio/vault-dm-crypt.git
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

Manage authentication credentials lifecycle (AppRole secret ID or Vault token):

```bash
# Check authentication status only (no changes)
vault-dm-crypt refresh-auth --status

# Default: refresh if less than 25% of lifetime remaining
# For AppRole: refreshes secret ID and updates config
# For Token: attempts to renew the token
vault-dm-crypt refresh-auth

# Force refresh regardless of expiry
vault-dm-crypt refresh-auth --force

# Refresh without updating config file (AppRole only)
vault-dm-crypt refresh-auth --no-update-config

# Custom threshold percentage (e.g., 50% = 0.5)
vault-dm-crypt refresh-auth --threshold-percentage 0.5
```

**Recommended Vault Token/AppRole Settings:**
- **Token TTL**: 24h (provides daily rotation)
- **Max Token TTL**: 7d (maximum lifetime)
- **Secret ID TTL**: 24h (for AppRole, provides daily rotation)
- **Refresh Threshold**: 25% of lifetime remaining (default)
- **Check Interval**: Every 15 minutes (via systemd timer)

With these settings:
- A 24h token/secret will be refreshed when it has 6 hours remaining
- The systemd timer checks every 15 minutes, ensuring timely refresh
- Tokens can be renewed up to 7 days before requiring re-authentication

### Automated Credential Refresh

For production environments, use the included systemd timer to automatically refresh credentials (token or AppRole secret ID):

```bash
# Install systemd units
sudo cp configs/systemd/vault-dm-crypt-refresh.service /etc/systemd/system/
sudo cp configs/systemd/vault-dm-crypt-refresh.timer /etc/systemd/system/
sudo systemctl daemon-reload

# Enable automatic refresh (runs every 15 minutes, refreshes at 25% lifetime remaining)
sudo systemctl enable vault-dm-crypt-refresh.timer
sudo systemctl start vault-dm-crypt-refresh.timer

# Check timer status
sudo systemctl status vault-dm-crypt-refresh.timer

# Monitor refresh activity
sudo journalctl -u vault-dm-crypt-refresh.service -f
```

**How the automatic refresh works:**
1. Timer runs every 15 minutes
2. Checks if token/secret ID has less than 25% of its lifetime remaining
3. For 24h credentials, refresh occurs when ~6h remain
4. For token auth: attempts to renew the token
5. For AppRole auth: generates new secret ID and updates config automatically

### Configuration

Configuration file is located at `/etc/vault-dm-crypt/config.toml`:

#### Option 1: Token Authentication

```toml
[vault]
url = "https://vault.example.com:8200"
backend = "secret"
kv_version = "1"  # KV store version: "1" or "2" (default: "1" for vaultlocker compatibility)
vault_path = "vault-dm-crypt/%h"  # Base path for storing keys (default: "vault-dm-crypt/%h", %h = short hostname)
vault_token = "your-vault-token"
ca_bundle = "/etc/ssl/certs/ca-certificates.crt"
timeout = 30
retry_max = 3
retry_delay = 5

[logging]
level = "info"
format = "json"
output = "/var/log/vault-dm-crypt.log"
```

#### Option 2: AppRole Authentication

```toml
[vault]
url = "https://vault.example.com:8200"
backend = "secret"
kv_version = "1"  # KV store version: "1" or "2" (default: "1" for vaultlocker compatibility)
vault_path = "vault-dm-crypt/%h"  # Base path for storing keys (default: "vault-dm-crypt/%h", %h = short hostname)
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

**Notes**:
- Use either `vault_token` OR `approle`/`secret_id`, not both. The two authentication methods are mutually exclusive.
- The `vault_path` supports the `%h` placeholder which is replaced with the short hostname of the machine. This allows organizing keys by hostname.
- For vaultlocker compatibility, set `vault_path = "vaultlocker"` (without hostname placeholder)

## Vault Configuration

### Required Permissions

vault-dm-crypt requires specific Vault policies depending on the authentication method used.

#### For Token Authentication

The token needs permissions to:
- Read and write secrets at `secret/data/vaultlocker/*`
- Renew itself (if the token is renewable)
- Look up its own token information

**Policy Example (KV v2):**

```hcl
# Policy for vault-dm-crypt with token authentication (KV v2)
# Adjust the path based on your vault_path config setting
# This example uses the default "vault-dm-crypt/*" with wildcard for all hosts
path "secret/data/vault-dm-crypt/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/vault-dm-crypt/*" {
  capabilities = ["list", "read", "delete"]
}

# For vaultlocker compatibility, use:
# path "secret/data/vaultlocker/*" { ... }
# path "secret/metadata/vaultlocker/*" { ... }

# Allow token to renew itself
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow token to look up its own properties
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
```

**Policy Example (KV v1):**

```hcl
# Policy for vault-dm-crypt with token authentication (KV v1)
# Adjust the path based on your vault_path config setting
# This example uses the default "vault-dm-crypt/*" with wildcard for all hosts
path "secret/vault-dm-crypt/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# For vaultlocker compatibility, use:
# path "secret/vaultlocker/*" { ... }

# Allow token to renew itself
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow token to look up its own properties
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
```

**Creating a Token:**

```bash
# Create a renewable periodic token with the vault-dm-crypt policy
# Recommended settings: 24h TTL with 7d max TTL
vault token create \
  -policy=vault-dm-crypt \
  -renewable=true \
  -ttl=24h \
  -explicit-max-ttl=168h \
  -period=24h \
  -display-name="vault-dm-crypt-token"

# The output will include the token to use in your config:
# Key                  Value
# ---                  -----
# token                hvs.CAESI...
# token_accessor       ...
# token_duration       24h
# token_renewable      true
# token_policies       ["vault-dm-crypt"]

# With these settings:
# - Token has 24h initial TTL
# - Can be renewed every 24h (period)
# - Maximum lifetime is 7 days (168h explicit-max-ttl)
# - Automatically refreshed when <25% lifetime remains (~6h before expiry)
```

#### For AppRole Authentication

The AppRole needs permissions to:
- Read and write secrets at `secret/data/vaultlocker/*`
- Generate new secret IDs for itself (for automatic refresh)
- Look up secret ID information

**Policy Example (KV v2):**

```hcl
# Policy for vault-dm-crypt with AppRole authentication (KV v2)
# Adjust the path based on your vault_path config setting
# This example uses the default "vault-dm-crypt/*" with wildcard for all hosts
path "secret/data/vault-dm-crypt/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/vault-dm-crypt/*" {
  capabilities = ["list", "read", "delete"]
}

# For vaultlocker compatibility, use:
# path "secret/data/vaultlocker/*" { ... }
# path "secret/metadata/vaultlocker/*" { ... }

# Allow AppRole to generate new secret IDs for itself
path "auth/approle/role/vault-dm-crypt/secret-id" {
  capabilities = ["update"]
}

# Allow AppRole to look up secret ID information
path "auth/approle/role/vault-dm-crypt/secret-id/lookup" {
  capabilities = ["update"]
}

# Allow token to look up its own properties
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
```

**Policy Example (KV v1):**

```hcl
# Policy for vault-dm-crypt with AppRole authentication (KV v1)
# Adjust the path based on your vault_path config setting
# This example uses the default "vault-dm-crypt/*" with wildcard for all hosts
path "secret/vault-dm-crypt/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# For vaultlocker compatibility, use:
# path "secret/vaultlocker/*" { ... }

# Allow AppRole to generate new secret IDs for itself
path "auth/approle/role/vault-dm-crypt/secret-id" {
  capabilities = ["update"]
}

# Allow AppRole to look up secret ID information
path "auth/approle/role/vault-dm-crypt/secret-id/lookup" {
  capabilities = ["update"]
}

# Allow token to look up its own properties
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
```

**Creating an AppRole:**

```bash
# Enable AppRole auth method if not already enabled
vault auth enable approle

# Create the AppRole with recommended settings
# Token: 24h TTL with 7d max, Secret ID: 24h TTL
vault write auth/approle/role/vault-dm-crypt \
  token_ttl=24h \
  token_max_ttl=168h \
  token_period=24h \
  secret_id_ttl=24h \
  secret_id_num_uses=0 \
  token_policies="vault-dm-crypt"

# Get the Role ID (use this as 'approle' in config.toml)
vault read auth/approle/role/vault-dm-crypt/role-id

# Generate a Secret ID (use this as 'secret_id' in config.toml)
vault write -field=secret_id auth/approle/role/vault-dm-crypt/secret-id

# Example output:
# Role ID: 12345678-1234-1234-1234-123456789abc
# Secret ID: 87654321-4321-4321-4321-cba987654321
```

**AppRole Configuration Recommendations:**

- `token_ttl`: Duration of tokens from AppRole login (24h recommended)
- `token_max_ttl`: Maximum lifetime of tokens (168h = 7d recommended)
- `token_period`: Renewal period for tokens (24h recommended)
- `secret_id_ttl`: How long a secret ID is valid (24h recommended for daily rotation)
- `secret_id_num_uses`: Number of times a secret ID can be used (0 = unlimited)
- The systemd timer checks every 15 minutes and refreshes when <25% lifetime remains
- With 24h secret ID TTL, refresh occurs automatically when ~6h remain

### Setting up the Vault KV Backend

vault-dm-crypt supports both KV v1 and KV v2 secrets engines. The version is controlled by the `kv_version` config option:

- **KV v1** (default): For backwards compatibility with vaultlocker. Use `kv_version = "1"` or omit (defaults to "1")
- **KV v2**: For versioned secrets with metadata. Use `kv_version = "2"`

**For KV v1 (vaultlocker compatibility):**

```bash
# Enable KV v1 secrets engine
vault secrets enable -path=secret kv

# Verify it's enabled
vault secrets list
```

**For KV v2 (recommended for new installations):**

```bash
# Enable KV v2 secrets engine
vault secrets enable -path=secret kv-v2

# Verify it's enabled
vault secrets list
```

**Note**: Make sure to set `kv_version` in your config.toml to match the actual KV version of your secrets engine.

### Quick Setup Script

```bash
#!/bin/bash
# Quick setup script for vault-dm-crypt Vault configuration

# Enable required auth and secrets engines
vault auth enable approle 2>/dev/null || true
vault secrets enable -path=secret kv-v2 2>/dev/null || true

# Create policy (adjust paths based on your KV version and vault_path setting)
# For KV v2, use: secret/data/vault-dm-crypt/* and secret/metadata/vault-dm-crypt/*
# For KV v1, use: secret/vault-dm-crypt/*
# For vaultlocker compatibility: secret/vaultlocker/* (KV v1) or secret/data/vaultlocker/* (KV v2)
vault policy write vault-dm-crypt - <<EOF
path "secret/vault-dm-crypt/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "auth/approle/role/vault-dm-crypt/secret-id" {
  capabilities = ["update"]
}

path "auth/approle/role/vault-dm-crypt/secret-id/lookup" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
EOF

# Create AppRole
vault write auth/approle/role/vault-dm-crypt \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=24h \
  secret_id_num_uses=0 \
  token_policies="vault-dm-crypt"

# Get credentials
echo "=== AppRole Credentials ==="
echo "Role ID:"
vault read -field=role_id auth/approle/role/vault-dm-crypt/role-id
echo ""
echo "Secret ID:"
vault write -field=secret_id auth/approle/role/vault-dm-crypt/secret-id
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
