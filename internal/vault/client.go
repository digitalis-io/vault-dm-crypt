package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"

	"digitalisio/vault-dm-crypt/internal/config"
	"digitalisio/vault-dm-crypt/internal/errors"
)

// Client wraps the Vault API client with additional functionality
type Client struct {
	client       *api.Client
	config       *config.VaultConfig
	logger       *logrus.Logger
	token        string
	tokenExp     time.Time
	authMethod   AuthMethod
	tokenManager *TokenManager
}

// NewClient creates a new Vault client with the provided configuration
func NewClient(cfg *config.VaultConfig, logger *logrus.Logger) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("vault configuration cannot be nil")
	}

	if logger == nil {
		return nil, errors.New("logger cannot be nil")
	}

	// Create Vault API config
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = cfg.URL
	vaultConfig.Timeout = cfg.Timeout()

	// Configure TLS if CA bundle is specified
	if cfg.CABundle != "" {
		tlsConfig := &api.TLSConfig{
			CACert: cfg.CABundle,
		}
		if err := vaultConfig.ConfigureTLS(tlsConfig); err != nil {
			return nil, errors.Wrap(err, "failed to configure TLS")
		}
	}

	// Create Vault client
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Vault client")
	}

	// Determine authentication method
	var authMethod AuthMethod
	if cfg.VaultToken != "" {
		// Use token authentication
		authMethod = NewTokenAuth(cfg.VaultToken, logger)
		logger.Debug("Using token authentication")
	} else {
		// Use AppRole authentication
		authMethod = NewAppRoleAuth(cfg.AppRole, cfg.SecretID, logger)
		logger.Debug("Using AppRole authentication")
	}

	// Create token manager with the chosen auth method
	tokenManager := NewTokenManager(client, authMethod, logger)

	return &Client{
		client:       client,
		config:       cfg,
		logger:       logger,
		authMethod:   authMethod,
		tokenManager: tokenManager,
	}, nil
}

// Authenticate performs authentication using the configured method
func (c *Client) Authenticate(ctx context.Context) error {
	// Use token manager for authentication
	if err := c.tokenManager.Authenticate(ctx); err != nil {
		return err
	}

	// Update local token and expiration info
	c.token = c.tokenManager.GetToken()
	c.tokenExp = c.tokenManager.GetExpiresAt()

	return nil
}

// IsTokenValid checks if the current token is valid and not expired
func (c *Client) IsTokenValid() bool {
	if c.token == "" {
		return false
	}

	// Check if token is expired (with 30 second buffer)
	if !c.tokenExp.IsZero() && time.Now().Add(30*time.Second).After(c.tokenExp) {
		return false
	}

	return true
}

// EnsureAuthenticated ensures the client has a valid token, re-authenticating if necessary
func (c *Client) EnsureAuthenticated(ctx context.Context) error {
	if c.IsTokenValid() {
		return nil
	}

	c.logger.Debug("Token invalid or expired, re-authenticating")
	return c.Authenticate(ctx)
}

// WriteSecret stores a secret at the specified path
func (c *Client) WriteSecret(ctx context.Context, path string, data map[string]interface{}) error {
	if err := c.EnsureAuthenticated(ctx); err != nil {
		return err
	}

	var fullPath string
	var secretData map[string]interface{}

	if c.config.KVVersion == "2" {
		// KV v2: wrap data and use /data/ path
		secretData = map[string]interface{}{
			"data": data,
		}
		fullPath = fmt.Sprintf("%s/data/%s", c.config.Backend, path)
	} else {
		// KV v1: write data directly
		secretData = data
		fullPath = fmt.Sprintf("%s/%s", c.config.Backend, path)
	}

	c.logger.WithFields(logrus.Fields{
		"path":       fullPath,
		"kv_version": c.config.KVVersion,
	}).Debug("Writing secret to Vault")

	_, err := c.client.Logical().WriteWithContext(ctx, fullPath, secretData)
	if err != nil {
		return errors.NewVaultWriteError(fullPath, err)
	}

	c.logger.WithField("path", fullPath).Info("Successfully wrote secret to Vault")
	return nil
}

// ReadSecret retrieves a secret from the specified path
func (c *Client) ReadSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	if err := c.EnsureAuthenticated(ctx); err != nil {
		return nil, err
	}

	var fullPath string
	if c.config.KVVersion == "2" {
		// KV v2: use /data/ path
		fullPath = fmt.Sprintf("%s/data/%s", c.config.Backend, path)
	} else {
		// KV v1: direct path
		fullPath = fmt.Sprintf("%s/%s", c.config.Backend, path)
	}

	c.logger.WithFields(logrus.Fields{
		"path":       fullPath,
		"kv_version": c.config.KVVersion,
	}).Debug("Reading secret from Vault")

	resp, err := c.client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return nil, errors.NewVaultReadError(fullPath, err)
	}

	if resp == nil {
		return nil, errors.NewVaultReadError(fullPath, fmt.Errorf("secret not found"))
	}

	if resp.Data == nil {
		return nil, errors.NewVaultReadError(fullPath, fmt.Errorf("no data in secret"))
	}

	var data map[string]interface{}
	if c.config.KVVersion == "2" {
		// KV v2: data is nested under "data" field
		var ok bool
		data, ok = resp.Data["data"].(map[string]interface{})
		if !ok {
			return nil, errors.NewVaultReadError(fullPath, fmt.Errorf("invalid data format in secret"))
		}
	} else {
		// KV v1: data is directly in resp.Data
		data = resp.Data
	}

	c.logger.WithField("path", fullPath).Debug("Successfully read secret from Vault")
	return data, nil
}

// WithRetry executes a function with retry logic
func (c *Client) WithRetry(ctx context.Context, operation func() error) error {
	var lastErr error

	for attempt := 0; attempt <= c.config.RetryMax; attempt++ {
		if attempt > 0 {
			c.logger.WithFields(logrus.Fields{
				"attempt":     attempt,
				"max_retries": c.config.RetryMax,
				"delay":       c.config.RetryDelay(),
			}).Warn("Retrying Vault operation")

			// Wait before retry
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.config.RetryDelay()):
			}
		}

		lastErr = operation()
		if lastErr == nil {
			return nil
		}

		c.logger.WithError(lastErr).WithField("attempt", attempt).Debug("Vault operation failed")
	}

	return errors.Wrap(lastErr, fmt.Sprintf("operation failed after %d retries", c.config.RetryMax))
}

// GetTokenExpiry returns the token expiration time
func (c *Client) GetTokenExpiry() time.Time {
	return c.tokenExp
}

// IsTokenExpiringWithin checks if the token will expire within the given duration
func (c *Client) IsTokenExpiringWithin(threshold time.Duration) bool {
	if c.tokenExp.IsZero() {
		// If no expiry is set, consider it as expiring
		return true
	}

	expiryThreshold := time.Now().Add(threshold)
	return c.tokenExp.Before(expiryThreshold)
}

// RefreshSecretID generates a new secret ID for the AppRole
// This requires the AppRoleName to be configured and the role to have the ability to generate its own secret IDs
func (c *Client) RefreshSecretID(ctx context.Context) (string, error) {
	// Check if using token authentication
	if c.config.VaultToken != "" {
		return "", errors.New("secret ID refresh not applicable for token authentication")
	}

	if c.config.AppRoleName == "" {
		return "", errors.New("approle_name not configured - required for generating new secret IDs")
	}

	c.logger.Debug("Attempting to refresh AppRole secret ID")

	// First, ensure we have a valid token
	if err := c.EnsureAuthenticated(ctx); err != nil {
		return "", errors.Wrap(err, "failed to authenticate before refreshing secret ID")
	}

	// Generate a new secret ID for the AppRole using the role name
	path := fmt.Sprintf("auth/approle/role/%s/secret-id", c.config.AppRoleName)

	resp, err := c.client.Logical().WriteWithContext(ctx, path, nil)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed to generate new secret ID (role name: %s)", c.config.AppRoleName))
	}

	if resp == nil || resp.Data == nil {
		return "", errors.New("empty response when generating secret ID")
	}

	secretID, ok := resp.Data["secret_id"].(string)
	if !ok {
		return "", errors.New("invalid secret_id in response")
	}

	// Get secret ID metadata for logging
	secretIDAccessor, _ := resp.Data["secret_id_accessor"].(string)

	c.logger.WithFields(logrus.Fields{
		"secret_id_accessor": secretIDAccessor,
		"role_name":          c.config.AppRoleName,
	}).Info("Successfully generated new secret ID")

	return secretID, nil
}

// RefreshToken attempts to renew the current token (for token authentication)
func (c *Client) RefreshToken(ctx context.Context) error {
	// Check if using token authentication
	if c.config.VaultToken == "" {
		return errors.New("token refresh only applicable for token authentication")
	}

	c.logger.Debug("Attempting to refresh Vault token")

	// Use the token manager to renew the token
	if err := c.tokenManager.Renew(ctx); err != nil {
		return errors.Wrap(err, "failed to refresh token")
	}

	// Update local token info
	c.token = c.tokenManager.GetToken()
	c.tokenExp = c.tokenManager.GetExpiresAt()

	c.logger.Info("Successfully refreshed Vault token")
	return nil
}

// GetTokenInfo retrieves information about the current token
func (c *Client) GetTokenInfo(ctx context.Context) (map[string]interface{}, error) {
	if err := c.EnsureAuthenticated(ctx); err != nil {
		return nil, err
	}

	resp, err := c.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to lookup token info")
	}

	if resp == nil || resp.Data == nil {
		return nil, errors.New("empty token info response")
	}

	return resp.Data, nil
}

// GetSecretIDInfo retrieves information about a specific secret ID, including its TTL
func (c *Client) GetSecretIDInfo(ctx context.Context, secretID string) (map[string]interface{}, error) {
	// Check if using token authentication
	if c.config.VaultToken != "" {
		return nil, errors.New("secret ID info not applicable for token authentication")
	}

	if c.config.AppRoleName == "" {
		return nil, errors.New("approle_name not configured - required for secret ID lookup")
	}

	if err := c.EnsureAuthenticated(ctx); err != nil {
		return nil, err
	}

	// Look up the secret ID information
	path := fmt.Sprintf("auth/approle/role/%s/secret-id/lookup", c.config.AppRoleName)
	data := map[string]interface{}{
		"secret_id": secretID,
	}

	resp, err := c.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("failed to lookup secret ID info (role name: %s)", c.config.AppRoleName))
	}

	if resp == nil || resp.Data == nil {
		return nil, errors.New("empty response from secret ID lookup")
	}

	return resp.Data, nil
}

// GetCurrentSecretIDInfo retrieves information about the currently configured secret ID
func (c *Client) GetCurrentSecretIDInfo(ctx context.Context) (map[string]interface{}, error) {
	return c.GetSecretIDInfo(ctx, c.config.SecretID)
}

// IsSecretIDExpiringWithin checks if the secret ID will expire within the given duration
func (c *Client) IsSecretIDExpiringWithin(ctx context.Context, threshold time.Duration) (bool, error) {
	// Check if using token authentication
	if c.config.VaultToken != "" {
		return false, errors.New("secret ID expiry check not applicable for token authentication")
	}

	if c.config.AppRoleName == "" {
		return false, errors.New("approle_name not configured - required for secret ID expiry check")
	}

	secretIDInfo, err := c.GetCurrentSecretIDInfo(ctx)
	if err != nil {
		return false, err
	}

	// Check if expiration_time is available
	expirationTimeStr, ok := secretIDInfo["expiration_time"].(string)
	if !ok || expirationTimeStr == "" {
		// If no expiration time, check if TTL is 0 (never expires)
		if ttl, ok := secretIDInfo["secret_id_ttl"].(json.Number); ok {
			ttlInt, _ := ttl.Int64()
			if ttlInt == 0 {
				c.logger.Debug("Secret ID has no expiration (TTL=0)")
				return false, nil
			}
		}
		c.logger.Debug("Secret ID expiration time not available")
		return false, nil
	}

	// Parse the expiration time (Vault uses RFC3339 format)
	expirationTime, err := time.Parse(time.RFC3339, expirationTimeStr)
	if err != nil {
		c.logger.WithError(err).Warn("Failed to parse secret ID expiration time")
		return false, errors.Wrap(err, "failed to parse secret ID expiration time")
	}

	// Check if expiration is within threshold
	expiryThreshold := time.Now().Add(threshold)
	isExpiring := expirationTime.Before(expiryThreshold)

	c.logger.WithFields(logrus.Fields{
		"expiration_time":   expirationTime.Format(time.RFC3339),
		"threshold_minutes": threshold.Minutes(),
		"is_expiring":       isExpiring,
	}).Debug("Secret ID expiry check")

	return isExpiring, nil
}

// Close performs any necessary cleanup
func (c *Client) Close() error {
	// Clear sensitive data
	c.token = ""
	c.tokenExp = time.Time{}

	if c.client != nil {
		c.client.SetToken("")
	}

	c.logger.Debug("Vault client closed")
	return nil
}
