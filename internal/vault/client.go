package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"

	"github.com/axonops/vault-dm-crypt/internal/config"
	"github.com/axonops/vault-dm-crypt/pkg/errors"
)

// Client wraps the Vault API client with additional functionality
type Client struct {
	client   *api.Client
	config   *config.VaultConfig
	logger   *logrus.Logger
	token    string
	tokenExp time.Time
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
	vaultConfig.Timeout = cfg.Timeout

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

	return &Client{
		client: client,
		config: cfg,
		logger: logger,
	}, nil
}

// Authenticate performs AppRole authentication and sets the client token
func (c *Client) Authenticate(ctx context.Context) error {
	c.logger.Debug("Starting AppRole authentication")

	// Prepare authentication data
	data := map[string]interface{}{
		"role_id":   c.config.AppRole,
		"secret_id": c.config.SecretID,
	}

	// Authenticate with AppRole
	resp, err := c.client.Logical().WriteWithContext(ctx, "auth/approle/login", data)
	if err != nil {
		return errors.Wrap(err, "AppRole authentication failed")
	}

	if resp == nil || resp.Auth == nil {
		return errors.New("empty authentication response from Vault")
	}

	// Set the token
	c.token = resp.Auth.ClientToken
	c.client.SetToken(c.token)

	// Calculate token expiration
	if resp.Auth.LeaseDuration > 0 {
		c.tokenExp = time.Now().Add(time.Duration(resp.Auth.LeaseDuration) * time.Second)
	}

	c.logger.WithFields(logrus.Fields{
		"lease_duration": resp.Auth.LeaseDuration,
		"renewable":      resp.Auth.Renewable,
		"policies":       resp.Auth.Policies,
	}).Info("Successfully authenticated with Vault")

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

	// For KV v2, we need to wrap the data
	secretData := map[string]interface{}{
		"data": data,
	}

	fullPath := fmt.Sprintf("%s/data/%s", c.config.Backend, path)

	c.logger.WithField("path", fullPath).Debug("Writing secret to Vault")

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

	fullPath := fmt.Sprintf("%s/data/%s", c.config.Backend, path)

	c.logger.WithField("path", fullPath).Debug("Reading secret from Vault")

	resp, err := c.client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return nil, errors.NewVaultReadError(fullPath, err)
	}

	if resp == nil {
		return nil, errors.NewVaultReadError(fullPath, fmt.Errorf("secret not found"))
	}

	// For KV v2, the actual data is nested under "data"
	if resp.Data == nil {
		return nil, errors.NewVaultReadError(fullPath, fmt.Errorf("no data in secret"))
	}

	data, ok := resp.Data["data"].(map[string]interface{})
	if !ok {
		return nil, errors.NewVaultReadError(fullPath, fmt.Errorf("invalid data format in secret"))
	}

	c.logger.WithField("path", fullPath).Debug("Successfully read secret from Vault")
	return data, nil
}

// DeleteSecret removes a secret from the specified path
func (c *Client) DeleteSecret(ctx context.Context, path string) error {
	if err := c.EnsureAuthenticated(ctx); err != nil {
		return err
	}

	fullPath := fmt.Sprintf("%s/data/%s", c.config.Backend, path)

	c.logger.WithField("path", fullPath).Debug("Deleting secret from Vault")

	_, err := c.client.Logical().DeleteWithContext(ctx, fullPath)
	if err != nil {
		return errors.NewVaultDeleteError(fullPath, err)
	}

	c.logger.WithField("path", fullPath).Info("Successfully deleted secret from Vault")
	return nil
}

// WithRetry executes a function with retry logic
func (c *Client) WithRetry(ctx context.Context, operation func() error) error {
	var lastErr error

	for attempt := 0; attempt <= c.config.RetryMax; attempt++ {
		if attempt > 0 {
			c.logger.WithFields(logrus.Fields{
				"attempt":     attempt,
				"max_retries": c.config.RetryMax,
				"delay":       c.config.RetryDelay,
			}).Warn("Retrying Vault operation")

			// Wait before retry
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.config.RetryDelay):
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
