package vault

import (
	"context"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"

	"axonops/vault-dm-crypt/internal/errors"
)

// AuthMethod represents different authentication methods
type AuthMethod interface {
	Authenticate(ctx context.Context, client *api.Client) (*api.Secret, error)
	GetName() string
}

// AppRoleAuth implements AppRole authentication
type AppRoleAuth struct {
	RoleID   string
	SecretID string
	logger   *logrus.Logger
}

// NewAppRoleAuth creates a new AppRole authentication method
func NewAppRoleAuth(roleID, secretID string, logger *logrus.Logger) *AppRoleAuth {
	return &AppRoleAuth{
		RoleID:   roleID,
		SecretID: secretID,
		logger:   logger,
	}
}

// Authenticate performs AppRole authentication
func (a *AppRoleAuth) Authenticate(ctx context.Context, client *api.Client) (*api.Secret, error) {
	if a.RoleID == "" {
		return nil, errors.New("AppRole ID cannot be empty")
	}

	if a.SecretID == "" {
		return nil, errors.New("Secret ID cannot be empty")
	}

	a.logger.Debug("Authenticating with AppRole")

	data := map[string]interface{}{
		"role_id":   a.RoleID,
		"secret_id": a.SecretID,
	}

	// Perform authentication
	resp, err := client.Logical().WriteWithContext(ctx, "auth/approle/login", data)
	if err != nil {
		return nil, errors.Wrap(err, "AppRole login failed")
	}

	if resp == nil {
		return nil, errors.New("empty response from AppRole authentication")
	}

	if resp.Auth == nil {
		return nil, errors.New("no authentication data in AppRole response")
	}

	a.logger.WithFields(logrus.Fields{
		"policies":       resp.Auth.Policies,
		"lease_duration": resp.Auth.LeaseDuration,
		"renewable":      resp.Auth.Renewable,
		"accessor":       resp.Auth.Accessor,
	}).Info("AppRole authentication successful")

	return resp, nil
}

// GetName returns the name of this authentication method
func (a *AppRoleAuth) GetName() string {
	return "approle"
}

// TokenManager handles token lifecycle
type TokenManager struct {
	client    *api.Client
	auth      AuthMethod
	logger    *logrus.Logger
	token     string
	renewable bool
	ttl       time.Duration
	expiresAt time.Time
}

// NewTokenManager creates a new token manager
func NewTokenManager(client *api.Client, auth AuthMethod, logger *logrus.Logger) *TokenManager {
	return &TokenManager{
		client: client,
		auth:   auth,
		logger: logger,
	}
}

// Authenticate performs initial authentication and sets up token management
func (tm *TokenManager) Authenticate(ctx context.Context) error {
	tm.logger.WithField("auth_method", tm.auth.GetName()).Debug("Starting authentication")

	resp, err := tm.auth.Authenticate(ctx, tm.client)
	if err != nil {
		return err
	}

	return tm.setTokenFromResponse(resp)
}

// setTokenFromResponse extracts token information from authentication response
func (tm *TokenManager) setTokenFromResponse(resp *api.Secret) error {
	if resp.Auth == nil {
		return errors.New("no authentication data in response")
	}

	tm.token = resp.Auth.ClientToken
	tm.renewable = resp.Auth.Renewable
	tm.ttl = time.Duration(resp.Auth.LeaseDuration) * time.Second

	if tm.ttl > 0 {
		tm.expiresAt = time.Now().Add(tm.ttl)
	}

	// Set token on client
	tm.client.SetToken(tm.token)

	tm.logger.WithFields(logrus.Fields{
		"renewable":   tm.renewable,
		"ttl_seconds": tm.ttl.Seconds(),
		"expires_at":  tm.expiresAt.Format(time.RFC3339),
	}).Info("Token set successfully")

	return nil
}

// IsValid checks if the current token is valid
func (tm *TokenManager) IsValid() bool {
	if tm.token == "" {
		return false
	}

	// Check expiration with 30-second buffer
	if !tm.expiresAt.IsZero() {
		bufferTime := time.Now().Add(30 * time.Second)
		if bufferTime.After(tm.expiresAt) {
			tm.logger.Debug("Token is near expiration")
			return false
		}
	}

	return true
}

// Renew attempts to renew the current token
func (tm *TokenManager) Renew(ctx context.Context) error {
	if tm.token == "" {
		return errors.New("no token to renew")
	}

	if !tm.renewable {
		tm.logger.Debug("Token is not renewable, will re-authenticate")
		return tm.Authenticate(ctx)
	}

	tm.logger.Debug("Renewing token")

	resp, err := tm.client.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		tm.logger.WithError(err).Warn("Token renewal failed, will re-authenticate")
		return tm.Authenticate(ctx)
	}

	if resp == nil || resp.Auth == nil {
		tm.logger.Warn("Empty renewal response, will re-authenticate")
		return tm.Authenticate(ctx)
	}

	// Update token information
	tm.ttl = time.Duration(resp.Auth.LeaseDuration) * time.Second
	if tm.ttl > 0 {
		tm.expiresAt = time.Now().Add(tm.ttl)
	}

	tm.logger.WithFields(logrus.Fields{
		"new_ttl_seconds": tm.ttl.Seconds(),
		"new_expires_at":  tm.expiresAt.Format(time.RFC3339),
	}).Info("Token renewed successfully")

	return nil
}

// EnsureValid ensures the token is valid, renewing or re-authenticating as necessary
func (tm *TokenManager) EnsureValid(ctx context.Context) error {
	if tm.IsValid() {
		return nil
	}

	if tm.token != "" && tm.renewable {
		// Try renewal first
		if err := tm.Renew(ctx); err == nil {
			return nil
		}
		// If renewal fails, fall through to re-authentication
	}

	// Re-authenticate
	tm.logger.Debug("Re-authenticating due to invalid token")
	return tm.Authenticate(ctx)
}

// Clear clears the token and related data
func (tm *TokenManager) Clear() {
	tm.token = ""
	tm.renewable = false
	tm.ttl = 0
	tm.expiresAt = time.Time{}

	if tm.client != nil {
		tm.client.SetToken("")
	}

	tm.logger.Debug("Token manager cleared")
}

// GetToken returns the current token
func (tm *TokenManager) GetToken() string {
	return tm.token
}

// GetTTL returns the current token TTL
func (tm *TokenManager) GetTTL() time.Duration {
	return tm.ttl
}

// GetExpiresAt returns when the token expires
func (tm *TokenManager) GetExpiresAt() time.Time {
	return tm.expiresAt
}
