package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/axonops/vault-dm-crypt/pkg/errors"
)

// Config represents the complete configuration structure
type Config struct {
	Vault   VaultConfig   `mapstructure:"vault"`
	Logging LoggingConfig `mapstructure:"logging"`
}

// VaultConfig contains Vault-specific configuration
type VaultConfig struct {
	URL            string `mapstructure:"url"`
	Backend        string `mapstructure:"backend"`
	AppRole        string `mapstructure:"approle"`
	SecretID       string `mapstructure:"secret_id"`
	CABundle       string `mapstructure:"ca_bundle"`
	TimeoutSecs    int    `mapstructure:"timeout"`
	RetryMax       int    `mapstructure:"retry_max"`
	RetryDelaySecs int    `mapstructure:"retry_delay"`
}

func (v VaultConfig) Timeout() time.Duration {
	return time.Duration(v.TimeoutSecs) * time.Second
}

func (v VaultConfig) RetryDelay() time.Duration {
	return time.Duration(v.RetryDelaySecs) * time.Second
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		Vault: VaultConfig{
			URL:            "http://127.0.0.1:8200",
			Backend:        "secret",
			TimeoutSecs:    30,
			RetryMax:       3,
			RetryDelaySecs: 5,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		},
	}
}

// Load reads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	config := DefaultConfig()

	// Set up viper
	v := viper.New()
	v.SetConfigType("toml")

	// Handle config file path
	if configPath != "" {
		// Use explicit config path
		v.SetConfigFile(configPath)
	} else {
		// Search for config in standard locations
		v.SetConfigName("config")
		v.AddConfigPath("/etc/vault-dm-crypt")
		v.AddConfigPath("/etc/vaultlocker") // Compatibility with Python vaultlocker
		v.AddConfigPath("./configs")
		v.AddConfigPath(".")
	}

	// Set up environment variable binding
	v.SetEnvPrefix("VAULT_DM_CRYPT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Bind specific environment variables for compatibility
	bindEnvironmentVariables(v)

	// Set defaults from DefaultConfig
	setDefaults(v, config)

	// Read the config file (if it exists)
	if err := v.ReadInConfig(); err != nil {
		// If config file is explicitly specified, fail on read error
		if configPath != "" {
			return nil, errors.NewConfigError("", fmt.Sprintf("failed to read config file %s: %v", configPath, err), nil)
		}
		// Otherwise, continue with defaults and environment variables
	}

	// Unmarshal config
	if err := v.Unmarshal(config); err != nil {
		return nil, errors.NewConfigError("", "failed to unmarshal config", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// bindEnvironmentVariables binds specific environment variables for compatibility
func bindEnvironmentVariables(v *viper.Viper) {
	// Vault environment variables (compatible with Vault CLI)
	v.BindEnv("vault.url", "VAULT_ADDR")
	v.BindEnv("vault.ca_bundle", "VAULT_CACERT")
	v.BindEnv("vault.approle", "VAULT_APPROLE", "VAULT_DM_CRYPT_VAULT_APPROLE")
	v.BindEnv("vault.secret_id", "VAULT_SECRET_ID", "VAULT_DM_CRYPT_VAULT_SECRET_ID")

	// Custom environment variables
	v.BindEnv("vault.backend", "VAULT_DM_CRYPT_VAULT_BACKEND")
	v.BindEnv("vault.timeout", "VAULT_DM_CRYPT_VAULT_TIMEOUT")
	v.BindEnv("vault.retry_max", "VAULT_DM_CRYPT_VAULT_RETRY_MAX")
	v.BindEnv("vault.retry_delay", "VAULT_DM_CRYPT_VAULT_RETRY_DELAY")

	// Logging environment variables
	v.BindEnv("logging.level", "VAULT_DM_CRYPT_LOG_LEVEL")
	v.BindEnv("logging.format", "VAULT_DM_CRYPT_LOG_FORMAT")
	v.BindEnv("logging.output", "VAULT_DM_CRYPT_LOG_OUTPUT")
}

// setDefaults sets default values in viper
func setDefaults(v *viper.Viper, config *Config) {
	v.SetDefault("vault.url", config.Vault.URL)
	v.SetDefault("vault.backend", config.Vault.Backend)
	v.SetDefault("vault.timeout", config.Vault.Timeout)
	v.SetDefault("vault.retry_max", config.Vault.RetryMax)
	v.SetDefault("vault.retry_delay", config.Vault.RetryDelay)
	v.SetDefault("logging.level", config.Logging.Level)
	v.SetDefault("logging.format", config.Logging.Format)
	v.SetDefault("logging.output", config.Logging.Output)
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate Vault configuration
	if c.Vault.URL == "" {
		return errors.NewConfigError("vault.url", "URL cannot be empty", nil)
	}

	if c.Vault.Backend == "" {
		return errors.NewConfigError("vault.backend", "backend cannot be empty", nil)
	}

	// AppRole and SecretID are required for authentication
	if c.Vault.AppRole == "" {
		return errors.NewConfigError("vault.approle", "AppRole ID is required for authentication", nil)
	}

	if c.Vault.SecretID == "" {
		return errors.NewConfigError("vault.secret_id", "Secret ID is required for authentication", nil)
	}

	// Validate CA bundle path if specified
	if c.Vault.CABundle != "" {
		if _, err := os.Stat(c.Vault.CABundle); err != nil {
			return errors.NewConfigError("vault.ca_bundle", fmt.Sprintf("CA bundle file not found: %s", c.Vault.CABundle), err)
		}
	}

	// Validate timeouts and retry settings
	if c.Vault.TimeoutSecs <= 0 {
		return errors.NewConfigError("vault.timeout", "timeout must be positive", nil)
	}

	if c.Vault.RetryMax < 0 {
		return errors.NewConfigError("vault.retry_max", "retry_max cannot be negative", nil)
	}

	if c.Vault.RetryDelaySecs < 0 {
		return errors.NewConfigError("vault.retry_delay", "retry_delay cannot be negative", nil)
	}

	// Validate logging configuration
	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true, "panic": true,
	}
	if !validLevels[strings.ToLower(c.Logging.Level)] {
		return errors.NewConfigError("logging.level", fmt.Sprintf("invalid log level: %s", c.Logging.Level), nil)
	}

	validFormats := map[string]bool{"text": true, "json": true}
	if !validFormats[strings.ToLower(c.Logging.Format)] {
		return errors.NewConfigError("logging.format", fmt.Sprintf("invalid log format: %s", c.Logging.Format), nil)
	}

	// Validate output path if it's a file
	if c.Logging.Output != "stdout" && c.Logging.Output != "stderr" {
		dir := filepath.Dir(c.Logging.Output)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return errors.NewConfigError("logging.output", fmt.Sprintf("log output directory does not exist: %s", dir), err)
		}
	}

	return nil
}

// LoadFromPythonConfig attempts to load configuration from Python vaultlocker format
// This provides backwards compatibility with existing vaultlocker installations
func LoadFromPythonConfig(configPath string) (*Config, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, errors.NewConfigError("", fmt.Sprintf("failed to read Python config file: %s", configPath), err)
	}

	config := DefaultConfig()
	values := make(map[string]string)

	// Parse simple key=value format
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			values[key] = value
		}
	}

	// Map Python config format to Go config
	if url, ok := values["url"]; ok {
		config.Vault.URL = url
	}
	if backend, ok := values["backend"]; ok {
		config.Vault.Backend = backend
	}
	if approle, ok := values["approle"]; ok {
		config.Vault.AppRole = approle
	}
	if secretID, ok := values["secret_id"]; ok {
		config.Vault.SecretID = secretID
	}
	if caBundle, ok := values["ca_bundle"]; ok {
		config.Vault.CABundle = caBundle
	}

	// Validate the converted configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}
