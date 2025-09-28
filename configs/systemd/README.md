# Systemd Units for vault-dm-crypt

This directory contains systemd service and timer units for automating vault-dm-crypt operations.

## Available Units

### 1. vault-dm-crypt-decrypt@.service
**Purpose**: Decrypt and mount encrypted devices during system boot.

**Usage**:
```bash
# Enable for a specific device UUID
sudo systemctl enable vault-dm-crypt-decrypt@<uuid>.service

# Example
sudo systemctl enable vault-dm-crypt-decrypt@550e8400-e29b-41d4-a716-446655440000.service
```

### 2. vault-dm-crypt-refresh.service + vault-dm-crypt-refresh.timer
**Purpose**: Automatically refresh AppRole secret IDs before they expire.

**Features**:
- Runs every 15 minutes with randomized delay (0-5 minutes)
- Default behavior: refreshes secret ID if it expires within 30 minutes
- Automatically updates the default config file (/etc/vault-dm-crypt/config.toml)
- Includes security hardening and proper logging

**Usage**:
```bash
# Enable the timer
sudo systemctl enable vault-dm-crypt-refresh.timer
sudo systemctl start vault-dm-crypt-refresh.timer

# Check status
sudo systemctl status vault-dm-crypt-refresh.timer
sudo systemctl list-timers vault-dm-crypt-refresh*

# View logs
sudo journalctl -u vault-dm-crypt-refresh.service -f
```

## Installation

1. **Copy the systemd units**:
   ```bash
   sudo cp configs/systemd/*.service /etc/systemd/system/
   sudo cp configs/systemd/*.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

2. **Install the vault-dm-crypt binary**:
   ```bash
   sudo cp vault-dm-crypt /usr/local/bin/
   sudo chmod +x /usr/local/bin/vault-dm-crypt
   ```

3. **Create your configuration**:
   ```bash
   sudo mkdir -p /etc/vault-dm-crypt
   sudo cp configs/config.toml.example /etc/vault-dm-crypt/config.toml
   # Edit the config file with your Vault settings
   sudo vim /etc/vault-dm-crypt/config.toml
   ```

## Configuration Requirements

For the refresh timer to work, your config file must include:
- `approle_name` - Required for generating new secret IDs
- Valid `approle` and `secret_id` - For initial authentication
- Proper Vault URL and backend settings

Example config section:
```toml
[vault]
url = "https://vault.example.com:8200"
backend = "secret"
approle = "12345678-1234-1234-1234-123456789012"
approle_name = "vault-dm-crypt-prod"  # Required for refresh
secret_id = "87654321-4321-4321-4321-210987654321"
```

## Monitoring

### Check Timer Status
```bash
# List all vault-dm-crypt timers
sudo systemctl list-timers vault-dm-crypt-*

# Check specific timer
sudo systemctl status vault-dm-crypt-refresh.timer
```

### View Logs
```bash
# Recent refresh attempts
sudo journalctl -u vault-dm-crypt-refresh.service --since "1 hour ago"

# Follow live logs
sudo journalctl -u vault-dm-crypt-refresh.service -f

# All vault-dm-crypt logs
sudo journalctl -t vault-dm-crypt --since today
```

### Expected Log Output

**When secret ID is not expiring**:
```
✅ Secret ID is not expiring within 30m0s, no refresh needed
✅ Authentication management completed successfully.
```

**When secret ID is refreshed**:
```
🔄 Secret ID expires within 30m0s, refreshing automatically
✅ New secret ID saved to config: /etc/vault-dm-crypt/config.toml
✅ New secret ID verified successfully
✅ Authentication management completed successfully.
```

## Security Considerations

The refresh service runs with the following security hardening:
- `NoNewPrivileges=true` - Prevents privilege escalation
- `PrivateTmp=true` - Isolated temporary directory
- `ProtectSystem=strict` - Read-only filesystem except for config directory
- `ReadWritePaths=/etc/vault-dm-crypt` - Only config directory is writable
- `ProtectHome=true` - No access to user home directories
- `Nice=10` - Lower CPU priority for background operation

## Troubleshooting

### Timer Not Running
```bash
# Check if timer is enabled and active
sudo systemctl is-enabled vault-dm-crypt-refresh.timer
sudo systemctl is-active vault-dm-crypt-refresh.timer

# Enable and start if needed
sudo systemctl enable vault-dm-crypt-refresh.timer
sudo systemctl start vault-dm-crypt-refresh.timer
```

### Authentication Failures
```bash
# Test manually (status only)
sudo vault-dm-crypt refresh-auth --status

# Test refresh with default behavior
sudo vault-dm-crypt refresh-auth

# Force refresh regardless of expiry
sudo vault-dm-crypt refresh-auth --force

# Check config file permissions
sudo ls -la /etc/vault-dm-crypt/config.toml
```

### High Frequency Refreshes
If secret IDs are being refreshed too frequently, check:
- Vault AppRole configuration (secret ID TTL settings)
- Threshold setting (default: 30 minutes, can be customized with --threshold-minutes)
- Timer frequency (default: every 15 minutes)

## Customization

### Change Refresh Frequency
Edit the timer unit and modify the `OnCalendar` setting:
```bash
sudo systemctl edit vault-dm-crypt-refresh.timer
```

Add override:
```ini
[Timer]
# Run every 30 minutes instead of 15
OnCalendar=*:0/30
```

### Change Threshold
Edit the service unit and modify the `ExecStart` line:
```bash
sudo systemctl edit vault-dm-crypt-refresh.service
```

Add override:
```ini
[Service]
# Use 2-hour threshold instead of default 30 minutes
ExecStart=
ExecStart=/usr/local/bin/vault-dm-crypt refresh-auth --threshold-minutes 120
```

### Skip Config Updates
To prevent automatic config file updates:
```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/vault-dm-crypt refresh-auth --no-update-config
```

After making changes:
```bash
sudo systemctl daemon-reload
sudo systemctl restart vault-dm-crypt-refresh.timer
```
