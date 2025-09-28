package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, "http://127.0.0.1:8200", config.Vault.URL)
	assert.Equal(t, "secret", config.Vault.Backend)
	assert.Equal(t, 30*time.Second, config.Vault.Timeout())
	assert.Equal(t, 3, config.Vault.RetryMax)
	assert.Equal(t, 5*time.Second, config.Vault.RetryDelay())
	assert.Equal(t, "info", config.Logging.Level)
	assert.Equal(t, "text", config.Logging.Format)
	assert.Equal(t, "stdout", config.Logging.Output)
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &Config{
				Vault: VaultConfig{
					URL:            "http://vault:8200",
					Backend:        "secret",
					AppRole:        "test-role",
					SecretID:       "test-secret",
					TimeoutSecs:    30,
					RetryMax:       3,
					RetryDelaySecs: 5,
				},
				Logging: LoggingConfig{
					Level:  "info",
					Format: "json",
					Output: "stdout",
				},
			},
			wantErr: false,
		},
		{
			name: "missing vault URL",
			config: &Config{
				Vault: VaultConfig{
					Backend:     "secret",
					AppRole:     "test-role",
					SecretID:    "test-secret",
					TimeoutSecs: 30,
				},
				Logging: LoggingConfig{
					Level:  "info",
					Format: "json",
					Output: "stdout",
				},
			},
			wantErr: true,
			errMsg:  "vault.url",
		},
		{
			name: "missing backend",
			config: &Config{
				Vault: VaultConfig{
					URL:         "http://vault:8200",
					AppRole:     "test-role",
					SecretID:    "test-secret",
					TimeoutSecs: 30,
				},
				Logging: LoggingConfig{
					Level:  "info",
					Format: "json",
					Output: "stdout",
				},
			},
			wantErr: true,
			errMsg:  "vault.backend",
		},
		{
			name: "missing approle",
			config: &Config{
				Vault: VaultConfig{
					URL:         "http://vault:8200",
					Backend:     "secret",
					SecretID:    "test-secret",
					TimeoutSecs: 30,
				},
				Logging: LoggingConfig{
					Level:  "info",
					Format: "json",
					Output: "stdout",
				},
			},
			wantErr: true,
			errMsg:  "vault.approle",
		},
		{
			name: "missing secret_id",
			config: &Config{
				Vault: VaultConfig{
					URL:         "http://vault:8200",
					Backend:     "secret",
					AppRole:     "test-role",
					TimeoutSecs: 30,
				},
				Logging: LoggingConfig{
					Level:  "info",
					Format: "json",
					Output: "stdout",
				},
			},
			wantErr: true,
			errMsg:  "vault.secret_id",
		},
		{
			name: "invalid log level",
			config: &Config{
				Vault: VaultConfig{
					URL:         "http://vault:8200",
					Backend:     "secret",
					AppRole:     "test-role",
					SecretID:    "test-secret",
					TimeoutSecs: 30,
				},
				Logging: LoggingConfig{
					Level:  "invalid",
					Format: "json",
					Output: "stdout",
				},
			},
			wantErr: true,
			errMsg:  "logging.level",
		},
		{
			name: "invalid log format",
			config: &Config{
				Vault: VaultConfig{
					URL:         "http://vault:8200",
					Backend:     "secret",
					AppRole:     "test-role",
					SecretID:    "test-secret",
					TimeoutSecs: 30,
				},
				Logging: LoggingConfig{
					Level:  "info",
					Format: "invalid",
					Output: "stdout",
				},
			},
			wantErr: true,
			errMsg:  "logging.format",
		},
		{
			name: "negative timeout",
			config: &Config{
				Vault: VaultConfig{
					URL:         "http://vault:8200",
					Backend:     "secret",
					AppRole:     "test-role",
					SecretID:    "test-secret",
					TimeoutSecs: -1,
				},
				Logging: LoggingConfig{
					Level:  "info",
					Format: "json",
					Output: "stdout",
				},
			},
			wantErr: true,
			errMsg:  "vault.timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	configContent := `
[vault]
url = "https://vault.example.com:8200"
backend = "kv"
approle = "test-approle"
secret_id = "test-secret-id"
timeout = 60
retry_max = 5
retry_delay = 10

[logging]
level = "debug"
format = "json"
output = "stderr"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config
	config, err := Load(configPath)
	require.NoError(t, err)

	// Verify values
	assert.Equal(t, "https://vault.example.com:8200", config.Vault.URL)
	assert.Equal(t, "kv", config.Vault.Backend)
	assert.Equal(t, "test-approle", config.Vault.AppRole)
	assert.Equal(t, "test-secret-id", config.Vault.SecretID)
	assert.Equal(t, 60*time.Second, config.Vault.Timeout())
	assert.Equal(t, 5, config.Vault.RetryMax)
	assert.Equal(t, 10*time.Second, config.Vault.RetryDelay())
	assert.Equal(t, "debug", config.Logging.Level)
	assert.Equal(t, "json", config.Logging.Format)
	assert.Equal(t, "stderr", config.Logging.Output)
}

func TestLoadConfigWithEnvironmentVariables(t *testing.T) {
	// Set environment variables
	_ = os.Setenv("VAULT_ADDR", "http://env-vault:8200")
	_ = os.Setenv("VAULT_APPROLE", "env-approle")
	_ = os.Setenv("VAULT_SECRET_ID", "env-secret")
	_ = os.Setenv("VAULT_DM_CRYPT_VAULT_BACKEND", "env-backend")
	_ = os.Setenv("VAULT_DM_CRYPT_LOG_LEVEL", "warn")

	defer func() {
		_ = os.Unsetenv("VAULT_ADDR")
		_ = os.Unsetenv("VAULT_APPROLE")
		_ = os.Unsetenv("VAULT_SECRET_ID")
		_ = os.Unsetenv("VAULT_DM_CRYPT_VAULT_BACKEND")
		_ = os.Unsetenv("VAULT_DM_CRYPT_LOG_LEVEL")
	}()

	// Load config (will use defaults and environment)
	config, err := Load("")
	require.NoError(t, err)

	// Verify environment variables override defaults
	assert.Equal(t, "http://env-vault:8200", config.Vault.URL)
	assert.Equal(t, "env-approle", config.Vault.AppRole)
	assert.Equal(t, "env-secret", config.Vault.SecretID)
	assert.Equal(t, "env-backend", config.Vault.Backend)
	assert.Equal(t, "warn", config.Logging.Level)
}

func TestLoadFromPythonConfig(t *testing.T) {
	// Create a temporary Python-style config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "vaultlocker.conf")

	configContent := `url = http://python-vault:8200
approle = python-approle
secret_id = python-secret
backend = python-backend
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config
	config, err := LoadFromPythonConfig(configPath)
	require.NoError(t, err)

	// Verify values
	assert.Equal(t, "http://python-vault:8200", config.Vault.URL)
	assert.Equal(t, "python-approle", config.Vault.AppRole)
	assert.Equal(t, "python-secret", config.Vault.SecretID)
	assert.Equal(t, "python-backend", config.Vault.Backend)
}

func TestConfigWithInvalidCABundle(t *testing.T) {
	config := &Config{
		Vault: VaultConfig{
			URL:         "http://vault:8200",
			Backend:     "secret",
			AppRole:     "test-role",
			SecretID:    "test-secret",
			CABundle:    "/non/existent/ca.pem",
			TimeoutSecs: 30,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}

	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "vault.ca_bundle")
}

func TestConfigWithValidCABundle(t *testing.T) {
	// Create a temporary CA file
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.pem")
	err := os.WriteFile(caPath, []byte("fake-ca-cert"), 0644)
	require.NoError(t, err)

	config := &Config{
		Vault: VaultConfig{
			URL:         "http://vault:8200",
			Backend:     "secret",
			AppRole:     "test-role",
			SecretID:    "test-secret",
			CABundle:    caPath,
			TimeoutSecs: 30,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}

	err = config.Validate()
	assert.NoError(t, err)
}
