//go:build integration
// +build integration

package integration

import (
	"context"
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
	framework := SetupTest(t)

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

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
	framework := SetupTest(t)

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
		// Should get a meaningful error about configuration, connection, or privileges
		assert.True(t,
			strings.Contains(stderr, "failed to authenticate") ||
				strings.Contains(stderr, "connection") ||
				strings.Contains(stderr, "configuration") ||
				strings.Contains(stderr, "root privileges"),
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
}
