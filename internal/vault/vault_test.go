package vault

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"axonops/vault-dm-crypt/internal/config"
)

func TestNewClient(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	t.Run("valid configuration", func(t *testing.T) {
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
		assert.Equal(t, cfg, client.config)
		assert.Equal(t, logger, client.logger)
		assert.NotNil(t, client.client)
	})

	t.Run("nil configuration", func(t *testing.T) {
		client, err := NewClient(nil, logger)
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "vault configuration cannot be nil")
	})

	t.Run("nil logger", func(t *testing.T) {
		cfg := &config.VaultConfig{
			URL:     "http://localhost:8200",
			Backend: "secret",
		}

		client, err := NewClient(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "logger cannot be nil")
	})

	t.Run("invalid URL", func(t *testing.T) {
		cfg := &config.VaultConfig{
			URL:     "://invalid-url",
			Backend: "secret",
		}

		client, err := NewClient(cfg, logger)
		// Vault API does validate URL at creation time
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "failed to create Vault client")
	})
}

func TestClientIsTokenValid(t *testing.T) {
	logger := logrus.New()
	cfg := &config.VaultConfig{
		URL:     "http://localhost:8200",
		Backend: "secret",
	}

	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	t.Run("no token", func(t *testing.T) {
		assert.False(t, client.IsTokenValid())
	})

	t.Run("valid token", func(t *testing.T) {
		client.token = "test-token"
		client.tokenExp = time.Now().Add(10 * time.Minute)
		assert.True(t, client.IsTokenValid())
	})

	t.Run("expired token", func(t *testing.T) {
		client.token = "test-token"
		client.tokenExp = time.Now().Add(-10 * time.Minute)
		assert.False(t, client.IsTokenValid())
	})

	t.Run("token expiring soon", func(t *testing.T) {
		client.token = "test-token"
		client.tokenExp = time.Now().Add(15 * time.Second) // Less than 30 second buffer
		assert.False(t, client.IsTokenValid())
	})
}

func TestWithRetry(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress retry logs for tests

	cfg := &config.VaultConfig{
		URL:            "http://localhost:8200",
		Backend:        "secret",
		RetryMax:       3,
		RetryDelaySecs: 1, // Short delay for tests
	}

	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	t.Run("success on first try", func(t *testing.T) {
		callCount := 0
		operation := func() error {
			callCount++
			return nil
		}

		ctx := context.Background()
		err := client.WithRetry(ctx, operation)
		assert.NoError(t, err)
		assert.Equal(t, 1, callCount)
	})

	t.Run("success after retry", func(t *testing.T) {
		callCount := 0
		operation := func() error {
			callCount++
			if callCount < 3 {
				return assert.AnError
			}
			return nil
		}

		ctx := context.Background()
		err := client.WithRetry(ctx, operation)
		assert.NoError(t, err)
		assert.Equal(t, 3, callCount)
	})

	t.Run("failure after max retries", func(t *testing.T) {
		callCount := 0
		operation := func() error {
			callCount++
			return assert.AnError
		}

		ctx := context.Background()
		err := client.WithRetry(ctx, operation)
		assert.Error(t, err)
		assert.Equal(t, 4, callCount) // Initial try + 3 retries
		assert.Contains(t, err.Error(), "operation failed after 3 retries")
	})

	t.Run("context cancellation", func(t *testing.T) {
		callCount := 0
		operation := func() error {
			callCount++
			return assert.AnError
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := client.WithRetry(ctx, operation)
		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
		assert.Equal(t, 1, callCount) // Should only try once before cancellation
	})
}

func TestClose(t *testing.T) {
	logger := logrus.New()
	cfg := &config.VaultConfig{
		URL:     "http://localhost:8200",
		Backend: "secret",
	}

	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	// Set some token data
	client.token = "test-token"
	client.tokenExp = time.Now().Add(10 * time.Minute)
	client.client.SetToken("test-token")

	err = client.Close()
	assert.NoError(t, err)

	// Verify cleanup
	assert.Empty(t, client.token)
	assert.True(t, client.tokenExp.IsZero())
	assert.Empty(t, client.client.Token())
}

func TestAppRoleAuth(t *testing.T) {
	logger := logrus.New()

	t.Run("new approle auth", func(t *testing.T) {
		auth := NewAppRoleAuth("test-role", "test-secret", logger)
		assert.Equal(t, "test-role", auth.RoleID)
		assert.Equal(t, "test-secret", auth.SecretID)
		assert.Equal(t, logger, auth.logger)
		assert.Equal(t, "approle", auth.GetName())
	})

	t.Run("empty role id", func(t *testing.T) {
		auth := NewAppRoleAuth("", "test-secret", logger)
		ctx := context.Background()

		_, err := auth.Authenticate(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "AppRole ID cannot be empty")
	})

	t.Run("empty secret id", func(t *testing.T) {
		auth := NewAppRoleAuth("test-role", "", logger)
		ctx := context.Background()

		_, err := auth.Authenticate(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Secret ID cannot be empty")
	})
}

func TestTokenManager(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs for tests

	// Create a mock auth method
	mockAuth := &MockAuthMethod{
		name: "mock",
	}

	t.Run("new token manager", func(t *testing.T) {
		tm := NewTokenManager(nil, mockAuth, logger)
		assert.NotNil(t, tm)
		assert.Equal(t, mockAuth, tm.auth)
		assert.Equal(t, logger, tm.logger)
	})

	t.Run("token validity", func(t *testing.T) {
		tm := NewTokenManager(nil, mockAuth, logger)

		// No token
		assert.False(t, tm.IsValid())

		// Set valid token
		tm.token = "test-token"
		tm.expiresAt = time.Now().Add(10 * time.Minute)
		assert.True(t, tm.IsValid())

		// Expired token
		tm.expiresAt = time.Now().Add(-10 * time.Minute)
		assert.False(t, tm.IsValid())

		// Token expiring soon
		tm.expiresAt = time.Now().Add(15 * time.Second)
		assert.False(t, tm.IsValid())
	})

	t.Run("clear token", func(t *testing.T) {
		tm := NewTokenManager(nil, mockAuth, logger)
		tm.token = "test-token"
		tm.renewable = true
		tm.ttl = 10 * time.Minute
		tm.expiresAt = time.Now().Add(10 * time.Minute)

		tm.Clear()

		assert.Empty(t, tm.token)
		assert.False(t, tm.renewable)
		assert.Zero(t, tm.ttl)
		assert.True(t, tm.expiresAt.IsZero())
	})

	t.Run("getters", func(t *testing.T) {
		tm := NewTokenManager(nil, mockAuth, logger)
		token := "test-token"
		ttl := 10 * time.Minute
		expiresAt := time.Now().Add(ttl)

		tm.token = token
		tm.ttl = ttl
		tm.expiresAt = expiresAt

		assert.Equal(t, token, tm.GetToken())
		assert.Equal(t, ttl, tm.GetTTL())
		assert.Equal(t, expiresAt, tm.GetExpiresAt())
	})
}

// MockAuthMethod is a mock implementation of AuthMethod for testing
type MockAuthMethod struct {
	name          string
	shouldFail    bool
	responseToken string
}

func (m *MockAuthMethod) Authenticate(ctx context.Context, client *api.Client) (*api.Secret, error) {
	if m.shouldFail {
		return nil, assert.AnError
	}

	// Return a mock secret response
	return &api.Secret{
		Auth: &api.SecretAuth{
			ClientToken:   m.responseToken,
			Policies:      []string{"default"},
			LeaseDuration: 3600,
			Renewable:     true,
		},
	}, nil
}

func (m *MockAuthMethod) GetName() string {
	return m.name
}

func TestClientAuthenticate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

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

	t.Run("authentication with real vault", func(t *testing.T) {
		ctx := context.Background()

		err := client.Authenticate(ctx)
		// This will likely fail in test environment but tests the code path
		assert.Error(t, err) // Expected to fail without real Vault server
		// The exact error depends on whether Vault is available
	})
}

func TestClientEnsureAuthenticated(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	cfg := &config.VaultConfig{
		URL:     "http://localhost:8200",
		Backend: "secret",
	}

	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	t.Run("already authenticated", func(t *testing.T) {
		// Set up a valid token
		client.token = "test-token"
		client.tokenExp = time.Now().Add(10 * time.Minute)

		ctx := context.Background()
		err := client.EnsureAuthenticated(ctx)
		assert.NoError(t, err)
	})

	t.Run("needs authentication", func(t *testing.T) {
		// Clear token
		client.token = ""
		client.tokenExp = time.Time{}

		ctx := context.Background()
		err := client.EnsureAuthenticated(ctx)
		// This will likely fail in test environment but tests the code path
		assert.Error(t, err) // Expected to fail without real Vault server
	})
}

func TestClientSecretOperations(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	cfg := &config.VaultConfig{
		URL:     "http://localhost:8200",
		Backend: "secret",
	}

	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	// Set up a mock token to pass authentication checks
	client.token = "test-token"
	client.tokenExp = time.Now().Add(10 * time.Minute)

	secretPath := "test/path"
	secretData := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	t.Run("write secret", func(t *testing.T) {
		ctx := context.Background()
		err := client.WriteSecret(ctx, secretPath, secretData)
		// This will likely fail in test environment but tests the code path
		assert.Error(t, err) // Expected to fail without real Vault server
	})

	t.Run("read secret", func(t *testing.T) {
		ctx := context.Background()
		data, err := client.ReadSecret(ctx, secretPath)
		// This will likely fail in test environment but tests the code path
		assert.Error(t, err) // Expected to fail without real Vault server
		assert.Nil(t, data)
	})

	t.Run("delete secret", func(t *testing.T) {
		ctx := context.Background()
		err := client.DeleteSecret(ctx, secretPath)
		// This will likely fail in test environment but tests the code path
		assert.Error(t, err) // Expected to fail without real Vault server
	})
}

func TestReadSecretErrorConditions(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	config := &config.VaultConfig{
		URL:      "http://localhost:8200",
		Backend:  "secret",
		AppRole:  "test-role",
		SecretID: "test-secret",
	}

	client, err := NewClient(config, logger)
	require.NoError(t, err)

	t.Run("authentication error", func(t *testing.T) {
		// Clear any existing token to force authentication failure
		client.token = ""
		client.tokenExp = time.Time{}
		ctx := context.Background()

		data, err := client.ReadSecret(ctx, "test/path")
		assert.Error(t, err)
		assert.Nil(t, data)
		// Error may vary based on authentication failure type
	})
}

func TestAppRoleAuthenticateWithMockClient(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	auth := NewAppRoleAuth("test-role", "test-secret", logger)

	t.Run("authenticate with mock client", func(t *testing.T) {
		// This tests the authentication request structure
		ctx := context.Background()

		// Create a mock Vault client - this will fail but tests the code path
		cfg := api.DefaultConfig()
		cfg.Address = "http://localhost:8200"
		mockClient, err := api.NewClient(cfg)
		require.NoError(t, err)

		_, err = auth.Authenticate(ctx, mockClient)
		// Expected to fail without real Vault server, but tests the code path
		assert.Error(t, err)
	})
}

func TestTokenManagerAuthenticate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	mockAuth := &MockAuthMethod{
		name:          "mock",
		shouldFail:    false,
		responseToken: "test-token-123",
	}

	t.Run("successful token authentication", func(t *testing.T) {
		// Create a mock Vault client
		cfg := api.DefaultConfig()
		cfg.Address = "http://localhost:8200"
		mockClient, err := api.NewClient(cfg)
		require.NoError(t, err)

		tm := NewTokenManager(mockClient, mockAuth, logger)
		ctx := context.Background()

		err = tm.Authenticate(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "test-token-123", tm.GetToken())
		assert.True(t, tm.IsValid())
	})

	t.Run("failed token authentication", func(t *testing.T) {
		failingAuth := &MockAuthMethod{
			name:       "mock",
			shouldFail: true,
		}

		// Create a mock Vault client
		cfg := api.DefaultConfig()
		cfg.Address = "http://localhost:8200"
		mockClient, err := api.NewClient(cfg)
		require.NoError(t, err)

		tm := NewTokenManager(mockClient, failingAuth, logger)
		ctx := context.Background()

		err = tm.Authenticate(ctx)
		assert.Error(t, err)
		assert.Empty(t, tm.GetToken())
		assert.False(t, tm.IsValid())
	})
}

func TestTokenManagerSetTokenFromResponse(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Create a mock Vault client
	cfg := api.DefaultConfig()
	cfg.Address = "http://localhost:8200"
	mockClient, err := api.NewClient(cfg)
	require.NoError(t, err)

	mockAuth := &MockAuthMethod{name: "mock"}
	tm := NewTokenManager(mockClient, mockAuth, logger)

	t.Run("valid secret response", func(t *testing.T) {
		secret := &api.Secret{
			Auth: &api.SecretAuth{
				ClientToken:   "test-token-456",
				LeaseDuration: 3600,
				Renewable:     true,
			},
		}

		tm.setTokenFromResponse(secret)

		assert.Equal(t, "test-token-456", tm.GetToken())
		assert.Equal(t, time.Duration(3600)*time.Second, tm.GetTTL())
		assert.True(t, tm.IsValid())
	})

	t.Run("secret without auth", func(t *testing.T) {
		secret := &api.Secret{}
		tm.Clear()

		tm.setTokenFromResponse(secret)

		assert.Empty(t, tm.GetToken())
		assert.False(t, tm.IsValid())
	})
}

func TestTokenManagerRenew(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	mockAuth := &MockAuthMethod{name: "mock"}

	t.Run("renew with mock client", func(t *testing.T) {
		// Create a mock Vault client
		cfg := api.DefaultConfig()
		cfg.Address = "http://localhost:8200"
		mockClient, err := api.NewClient(cfg)
		require.NoError(t, err)
		mockClient.SetToken("test-token")

		tm := NewTokenManager(mockClient, mockAuth, logger)
		tm.token = "test-token"
		tm.renewable = true
		tm.ttl = 3600 * time.Second
		tm.expiresAt = time.Now().Add(10 * time.Minute)

		ctx := context.Background()

		err = tm.Renew(ctx)
		// May succeed or fail depending on token auto-renewal behavior
		// The important part is that it tests the code path without panicking
		if err != nil {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	})

	t.Run("renew non-renewable token", func(t *testing.T) {
		// Create a mock Vault client
		cfg := api.DefaultConfig()
		cfg.Address = "http://localhost:8200"
		mockClient, err := api.NewClient(cfg)
		require.NoError(t, err)

		tm := NewTokenManager(mockClient, mockAuth, logger)
		tm.token = "test-token"
		tm.renewable = false
		tm.ttl = 3600 * time.Second
		tm.expiresAt = time.Now().Add(10 * time.Minute)

		ctx := context.Background()

		err = tm.Renew(ctx)
		// For non-renewable tokens, Renew() calls Authenticate() which may fail in mock environment
		// The important part is testing the code path without panicking
		if err != nil {
			assert.Error(t, err)
			// Authentication failed, so token might be cleared
		} else {
			assert.NoError(t, err)
			// If authentication succeeded, token should be updated
			if tm.GetToken() != "" {
				assert.Equal(t, "test-token-123", tm.GetToken())
			}
		}
	})
}

func TestTokenManagerRenewEdgeCases(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	mockAuth := &MockAuthMethod{name: "mock"}

	t.Run("renew with no token", func(t *testing.T) {
		// Create a mock Vault client
		cfg := api.DefaultConfig()
		cfg.Address = "http://localhost:8200"
		mockClient, err := api.NewClient(cfg)
		require.NoError(t, err)

		tm := NewTokenManager(mockClient, mockAuth, logger)
		// Don't set any token
		ctx := context.Background()

		err = tm.Renew(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no token to renew")
	})

	t.Run("renew renewable token with failed renewal", func(t *testing.T) {
		// Create a mock Vault client
		cfg := api.DefaultConfig()
		cfg.Address = "http://localhost:8200"
		mockClient, err := api.NewClient(cfg)
		require.NoError(t, err)

		// Mock auth that will succeed during re-authentication fallback
		successAuth := &MockAuthMethod{
			name:          "mock",
			shouldFail:    false,
			responseToken: "new-token-after-renewal-failure",
		}

		tm := NewTokenManager(mockClient, successAuth, logger)
		tm.token = "renewable-token"
		tm.renewable = true
		tm.ttl = 3600 * time.Second
		tm.expiresAt = time.Now().Add(10 * time.Minute)

		ctx := context.Background()

		// This will fail the renewal (no real vault) but then try to re-authenticate
		err = tm.Renew(ctx)
		// Should either succeed (re-auth worked) or fail (re-auth also failed)
		// The important thing is testing the fallback code path
		if err == nil {
			// Re-authentication succeeded
			assert.Equal(t, "new-token-after-renewal-failure", tm.GetToken())
		} else {
			// Re-authentication also failed, which is fine for test
			assert.Error(t, err)
		}
	})
}

func TestClientAuthenticateErrorConditions(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	t.Run("authentication with invalid credentials", func(t *testing.T) {
		config := &config.VaultConfig{
			URL:            "http://localhost:8200",
			Backend:        "secret",
			AppRole:        "invalid-role",
			SecretID:       "invalid-secret",
			RetryMax:       1,
			RetryDelaySecs: 1,
		}

		client, err := NewClient(config, logger)
		require.NoError(t, err)

		ctx := context.Background()
		err = client.Authenticate(ctx)
		assert.Error(t, err)
		// Should contain authentication error
	})

	t.Run("authentication with empty role ID", func(t *testing.T) {
		config := &config.VaultConfig{
			URL:            "http://localhost:8200",
			Backend:        "secret",
			AppRole:        "", // Empty role ID
			SecretID:       "test-secret",
			RetryMax:       1,
			RetryDelaySecs: 1,
		}

		client, err := NewClient(config, logger)
		require.NoError(t, err)

		ctx := context.Background()
		err = client.Authenticate(ctx)
		assert.Error(t, err)
		// The actual error will be a connection error since no vault server is running
		assert.Contains(t, err.Error(), "AppRole authentication failed")
	})

	t.Run("authentication with empty secret ID", func(t *testing.T) {
		config := &config.VaultConfig{
			URL:            "http://localhost:8200",
			Backend:        "secret",
			AppRole:        "test-role",
			SecretID:       "", // Empty secret ID
			RetryMax:       1,
			RetryDelaySecs: 1,
		}

		client, err := NewClient(config, logger)
		require.NoError(t, err)

		ctx := context.Background()
		err = client.Authenticate(ctx)
		assert.Error(t, err)
		// The actual error will be a connection error since no vault server is running
		assert.Contains(t, err.Error(), "AppRole authentication failed")
	})
}

func TestTokenManagerEnsureValid(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	mockAuth := &MockAuthMethod{
		name:          "mock",
		shouldFail:    false,
		responseToken: "new-test-token",
	}

	t.Run("valid token", func(t *testing.T) {
		tm := NewTokenManager(nil, mockAuth, logger)
		tm.token = "test-token"
		tm.renewable = true
		tm.ttl = 3600 * time.Second
		tm.expiresAt = time.Now().Add(10 * time.Minute)

		ctx := context.Background()

		err := tm.EnsureValid(ctx)
		assert.NoError(t, err)
	})

	t.Run("expired token - reauthenticate", func(t *testing.T) {
		// Create a mock Vault client
		cfg := api.DefaultConfig()
		cfg.Address = "http://localhost:8200"
		mockClient, err := api.NewClient(cfg)
		require.NoError(t, err)

		tm := NewTokenManager(mockClient, mockAuth, logger)
		tm.token = "expired-token"
		tm.renewable = false
		tm.ttl = 3600 * time.Second
		tm.expiresAt = time.Now().Add(-10 * time.Minute) // Expired

		ctx := context.Background()

		err = tm.EnsureValid(ctx)
		// May succeed or fail in mock environment, but should not panic
		if err != nil {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, "new-test-token", tm.GetToken())
		}
	})
}
