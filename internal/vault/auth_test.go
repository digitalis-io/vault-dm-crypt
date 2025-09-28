package vault

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"axonops/vault-dm-crypt/internal/config"
)

// MockVaultClient is a mock implementation for testing
type MockVaultClient struct {
	mock.Mock
}

func (m *MockVaultClient) SetToken(token string) {
	m.Called(token)
}

func (m *MockVaultClient) Token() string {
	args := m.Called()
	return args.String(0)
}

// Test TokenAuth implementation
func TestTokenAuth_Authenticate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	t.Run("successful token authentication", func(t *testing.T) {
		// This test would require a mock Vault client
		// For now, we'll test the basic validation
		auth := NewTokenAuth("test-token", logger)
		assert.NotNil(t, auth)
		assert.Equal(t, "test-token", auth.Token)
		assert.Equal(t, "token", auth.GetName())
	})

	t.Run("empty token", func(t *testing.T) {
		auth := NewTokenAuth("", logger)

		// Create a mock client for testing
		client := &api.Client{}

		// Try to authenticate with empty token
		ctx := context.Background()
		resp, err := auth.Authenticate(ctx, client)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "Vault token cannot be empty")
	})

	t.Run("token auth method name", func(t *testing.T) {
		auth := NewTokenAuth("test-token", logger)
		assert.Equal(t, "token", auth.GetName())
	})
}

// Test AppRoleAuth implementation
func TestAppRoleAuth_Authenticate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	t.Run("successful approle creation", func(t *testing.T) {
		auth := NewAppRoleAuth("role-id", "secret-id", logger)
		assert.NotNil(t, auth)
		assert.Equal(t, "role-id", auth.RoleID)
		assert.Equal(t, "secret-id", auth.SecretID)
		assert.Equal(t, "approle", auth.GetName())
	})

	t.Run("empty role ID", func(t *testing.T) {
		auth := NewAppRoleAuth("", "secret-id", logger)

		// Create a mock client for testing
		client := &api.Client{}

		ctx := context.Background()
		resp, err := auth.Authenticate(ctx, client)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "AppRole ID cannot be empty")
	})

	t.Run("empty secret ID", func(t *testing.T) {
		auth := NewAppRoleAuth("role-id", "", logger)

		// Create a mock client for testing
		client := &api.Client{}

		ctx := context.Background()
		resp, err := auth.Authenticate(ctx, client)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "Secret ID cannot be empty")
	})

	t.Run("approle auth method name", func(t *testing.T) {
		auth := NewAppRoleAuth("role-id", "secret-id", logger)
		assert.Equal(t, "approle", auth.GetName())
	})
}

// Test TokenManager
func TestTokenManagerAuth(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	t.Run("token manager creation", func(t *testing.T) {
		client := &api.Client{}
		auth := NewTokenAuth("test-token", logger)
		tm := NewTokenManager(client, auth, logger)

		assert.NotNil(t, tm)
		assert.Equal(t, client, tm.client)
		assert.Equal(t, auth, tm.auth)
		assert.Equal(t, logger, tm.logger)
	})

	t.Run("token validity check", func(t *testing.T) {
		client := &api.Client{}
		auth := NewTokenAuth("test-token", logger)
		tm := NewTokenManager(client, auth, logger)

		// Initially invalid (no token set)
		assert.False(t, tm.IsValid())

		// Set token directly
		tm.token = "test-token"
		tm.expiresAt = time.Now().Add(10 * time.Minute)
		assert.True(t, tm.IsValid())

		// Expired token
		tm.expiresAt = time.Now().Add(-10 * time.Minute)
		assert.False(t, tm.IsValid())

		// Near expiration (within 30 second buffer)
		tm.expiresAt = time.Now().Add(15 * time.Second)
		assert.False(t, tm.IsValid())
	})

	t.Run("token manager clear", func(t *testing.T) {
		client := &api.Client{}
		auth := NewTokenAuth("test-token", logger)
		tm := NewTokenManager(client, auth, logger)

		// Set some values
		tm.token = "test-token"
		tm.renewable = true
		tm.ttl = 3600 * time.Second
		tm.expiresAt = time.Now().Add(1 * time.Hour)

		// Clear
		tm.Clear()

		// Verify cleared
		assert.Empty(t, tm.token)
		assert.False(t, tm.renewable)
		assert.Equal(t, time.Duration(0), tm.ttl)
		assert.True(t, tm.expiresAt.IsZero())
	})

	t.Run("token manager getters", func(t *testing.T) {
		client := &api.Client{}
		auth := NewTokenAuth("test-token", logger)
		tm := NewTokenManager(client, auth, logger)

		// Set values
		expectedToken := "test-token-123"
		expectedTTL := 3600 * time.Second
		expectedExpiry := time.Now().Add(1 * time.Hour)

		tm.token = expectedToken
		tm.ttl = expectedTTL
		tm.expiresAt = expectedExpiry

		// Test getters
		assert.Equal(t, expectedToken, tm.GetToken())
		assert.Equal(t, expectedTTL, tm.GetTTL())
		assert.Equal(t, expectedExpiry, tm.GetExpiresAt())
	})
}

// Test setting token from response
func TestTokenManager_SetTokenFromResponse(t *testing.T) {
	logger := logrus.New()
	client := &api.Client{}
	auth := NewTokenAuth("test-token", logger)
	tm := NewTokenManager(client, auth, logger)

	t.Run("valid response", func(t *testing.T) {
		resp := &api.Secret{
			Auth: &api.SecretAuth{
				ClientToken:   "new-token",
				Renewable:     true,
				LeaseDuration: 3600,
			},
		}

		err := tm.setTokenFromResponse(resp)
		require.NoError(t, err)

		assert.Equal(t, "new-token", tm.token)
		assert.True(t, tm.renewable)
		assert.Equal(t, 3600*time.Second, tm.ttl)
		assert.False(t, tm.expiresAt.IsZero())
	})

	t.Run("nil auth in response", func(t *testing.T) {
		resp := &api.Secret{
			Auth: nil,
		}

		err := tm.setTokenFromResponse(resp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no authentication data in response")
	})
}

// Test the integration of TokenAuth with config
func TestClientWithTokenAuth(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	t.Run("client with token authentication", func(t *testing.T) {
		cfg := &config.VaultConfig{
			URL:            "http://localhost:8200",
			Backend:        "secret",
			VaultToken:     "test-token-123",
			TimeoutSecs:    30,
			RetryMax:       3,
			RetryDelaySecs: 5,
		}

		client, err := NewClient(cfg, logger)
		require.NoError(t, err)
		assert.NotNil(t, client)

		// Verify that TokenAuth was chosen
		assert.NotNil(t, client.authMethod)
		assert.Equal(t, "token", client.authMethod.GetName())

		// Verify the token is set in the auth method
		if tokenAuth, ok := client.authMethod.(*TokenAuth); ok {
			assert.Equal(t, "test-token-123", tokenAuth.Token)
		} else {
			t.Error("Expected TokenAuth but got different type")
		}
	})

	t.Run("client with approle authentication", func(t *testing.T) {
		cfg := &config.VaultConfig{
			URL:            "http://localhost:8200",
			Backend:        "secret",
			AppRole:        "test-role",
			SecretID:       "test-secret",
			TimeoutSecs:    30,
			RetryMax:       3,
			RetryDelaySecs: 5,
		}

		client, err := NewClient(cfg, logger)
		require.NoError(t, err)
		assert.NotNil(t, client)

		// Verify that AppRoleAuth was chosen
		assert.NotNil(t, client.authMethod)
		assert.Equal(t, "approle", client.authMethod.GetName())

		// Verify the credentials are set in the auth method
		if appRoleAuth, ok := client.authMethod.(*AppRoleAuth); ok {
			assert.Equal(t, "test-role", appRoleAuth.RoleID)
			assert.Equal(t, "test-secret", appRoleAuth.SecretID)
		} else {
			t.Error("Expected AppRoleAuth but got different type")
		}
	})
}

// Test refresh methods with token authentication
func TestClientTokenRefresh(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	t.Run("refresh token with token auth", func(t *testing.T) {
		cfg := &config.VaultConfig{
			URL:        "http://localhost:8200",
			Backend:    "secret",
			VaultToken: "test-token",
		}

		client, err := NewClient(cfg, logger)
		require.NoError(t, err)

		// RefreshToken should only work with token auth
		// This would fail in real scenario without a mock, but we're testing the logic
		ctx := context.Background()
		err = client.RefreshToken(ctx)
		// The actual renewal would fail without a real Vault server
		// But we're testing that it doesn't return "not applicable" error
		assert.NotContains(t, err.Error(), "only applicable for token authentication")
	})

	t.Run("refresh token with approle auth should fail", func(t *testing.T) {
		cfg := &config.VaultConfig{
			URL:      "http://localhost:8200",
			Backend:  "secret",
			AppRole:  "test-role",
			SecretID: "test-secret",
		}

		client, err := NewClient(cfg, logger)
		require.NoError(t, err)

		ctx := context.Background()
		err = client.RefreshToken(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token refresh only applicable for token authentication")
	})

	t.Run("refresh secret ID with token auth should fail", func(t *testing.T) {
		cfg := &config.VaultConfig{
			URL:        "http://localhost:8200",
			Backend:    "secret",
			VaultToken: "test-token",
		}

		client, err := NewClient(cfg, logger)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.RefreshSecretID(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret ID refresh not applicable for token authentication")
	})

	t.Run("get secret ID info with token auth should fail", func(t *testing.T) {
		cfg := &config.VaultConfig{
			URL:        "http://localhost:8200",
			Backend:    "secret",
			VaultToken: "test-token",
		}

		client, err := NewClient(cfg, logger)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.GetSecretIDInfo(ctx, "some-secret-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret ID info not applicable for token authentication")
	})

	t.Run("check secret ID expiry with token auth should fail", func(t *testing.T) {
		cfg := &config.VaultConfig{
			URL:        "http://localhost:8200",
			Backend:    "secret",
			VaultToken: "test-token",
		}

		client, err := NewClient(cfg, logger)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.IsSecretIDExpiringWithin(ctx, 30*time.Minute)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret ID expiry check not applicable for token authentication")
	})
}
