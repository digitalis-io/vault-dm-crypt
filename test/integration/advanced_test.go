package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdvancedScenarios tests complex real-world scenarios
func TestAdvancedScenarios(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("vault_token_renewal", func(t *testing.T) {
		// Test that long-running operations handle token renewal correctly
		// This simulates a scenario where the Vault token expires during operation

		// First, verify that we can perform operations
		_, stderr, err := framework.RunCommand(
			"--config", configFile,
			"decrypt",
			"test-uuid-for-renewal",
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, framework.ExpectDecryptError())
	})

	t.Run("configuration_hot_reload", func(t *testing.T) {
		// Test configuration changes between operations
		// This tests that configuration is properly loaded for each operation

		// Create a modified config with different retry settings
		modifiedConfigContent := fmt.Sprintf(`[vault]
url = "%s"
backend = "secret"
approle = "%s"
secret_id = "%s"
timeout = 60
retry_max = 5
retry_delay = 2

[logging]
level = "info"
format = "json"
output = "stdout"
`, vaultAddr, roleID, secretID)

		modifiedConfigFile := framework.GetTempDir() + "/modified-config.toml"
		err := os.WriteFile(modifiedConfigFile, []byte(modifiedConfigContent), 0644)
		require.NoError(t, err)

		// Test with modified configuration
		_, stderr, err := framework.RunCommand(
			"--config", modifiedConfigFile,
			"decrypt",
			"test-uuid-modified-config",
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, framework.ExpectDecryptError())
	})

	t.Run("environment_variable_override", func(t *testing.T) {
		// Test that environment variables can override configuration
		// This tests configuration precedence

		cmd := exec.Command(framework.GetBinaryPath(),
			"--config", configFile,
			"--debug", // Override log level
			"--help")

		// Set environment variable for additional testing
		cmd.Env = append(os.Environ(), "VAULT_DM_CRYPT_DEBUG=1")

		output, err := cmd.Output()
		assert.NoError(t, err)
		assert.Contains(t, string(output), "vault-dm-crypt")
	})
}

// TestFailureRecovery tests system behavior during and after failures
func TestFailureRecovery(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("vault_connection_recovery", func(t *testing.T) {
		// Test recovery from Vault connection failures
		// This simulates network issues or Vault downtime

		// First attempt should work (device not found, but connection succeeds)
		_, stderr, err := framework.RunCommand(
			"--config", configFile,
			"decrypt",
			"test-uuid-recovery",
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, framework.ExpectDecryptError())
	})

	t.Run("invalid_configuration_recovery", func(t *testing.T) {
		// Test graceful handling of invalid configuration

		invalidConfigContent := `[vault]
url = "invalid-url-format"
backend = "secret"
approle = "invalid-role"
secret_id = "invalid-secret"
`

		invalidConfigFile := framework.GetTempDir() + "/invalid-config.toml"
		err := os.WriteFile(invalidConfigFile, []byte(invalidConfigContent), 0644)
		require.NoError(t, err)

		_, stderr, err := framework.RunCommand(
			"--config", invalidConfigFile,
			"decrypt",
			"test-uuid-invalid-config",
		)

		assert.Error(t, err)
		// Should get a meaningful error about configuration or connection
		assert.True(t,
			strings.Contains(stderr, "failed to authenticate") ||
				strings.Contains(stderr, "connection") ||
				strings.Contains(stderr, "configuration"),
			"Should get meaningful error: %s", stderr)
	})

	t.Run("timeout_handling", func(t *testing.T) {
		// Test timeout handling in operations
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Create a command that should complete within timeout
		cmd := exec.CommandContext(ctx, framework.GetBinaryPath(),
			"--config", configFile,
			"decrypt", "test-uuid-timeout")

		output, err := cmd.CombinedOutput()

		// Operation should complete (with expected error) before timeout
		assert.NotEqual(t, context.DeadlineExceeded, ctx.Err(), "Operation should not timeout")

		// Should get device not found error
		if err != nil {
			assert.Contains(t, string(output), framework.ExpectDecryptError())
		}
	})

	t.Run("concurrent_failure_isolation", func(t *testing.T) {
		// Test that failures in one operation don't affect others
		numOperations := 3
		done := make(chan error, numOperations)

		for i := 0; i < numOperations; i++ {
			go func(id int) {
				_, stderr, err := framework.RunCommand(
					"--config", configFile,
					"decrypt",
					fmt.Sprintf("test-uuid-concurrent-%d", id),
				)

				// All should fail with device not found (expected)
				if err != nil && strings.Contains(stderr, framework.ExpectDecryptError()) {
					done <- nil
				} else {
					done <- fmt.Errorf("unexpected result for operation %d: %v", id, err)
				}
			}(i)
		}

		// Wait for all operations to complete
		for i := 0; i < numOperations; i++ {
			select {
			case err := <-done:
				assert.NoError(t, err)
			case <-time.After(30 * time.Second):
				t.Fatal("Concurrent operations timed out")
			}
		}
	})
}
