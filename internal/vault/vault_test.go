package vault

import (
	"context"
	"testing"
	"time"

	"github.com/axonops/vault-dm-crypt/internal/config"
	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	t.Run("valid configuration", func(t *testing.T) {
		cfg := &config.VaultConfig{
			URL:        "http://localhost:8200",
			Backend:    "secret",
			AppRole:    "test-role",
			SecretID:   "test-secret",
			Timeout:    30 * time.Second,
			RetryMax:   3,
			RetryDelay: 5 * time.Second,
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
		URL:        "http://localhost:8200",
		Backend:    "secret",
		RetryMax:   3,
		RetryDelay: 10 * time.Millisecond, // Short delay for tests
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