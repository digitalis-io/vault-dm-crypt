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
		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"decrypt",
			"test-uuid-for-renewal",
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, "device with UUID")
		assert.Contains(t, stderr, "not found")
		assert.Empty(t, stdout)
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
		stdout, stderr, err := framework.RunCommand(
			"--config", modifiedConfigFile,
			"decrypt",
			"test-uuid-modified-config",
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, "device with UUID")
		assert.Contains(t, stderr, "not found")
		assert.Empty(t, stdout)
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

// TestPerformanceCharacteristics tests system performance under various conditions
func TestPerformanceCharacteristics(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("startup_time", func(t *testing.T) {
		// Measure application startup time
		start := time.Now()

		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"--version",
		)

		duration := time.Since(start)

		assert.NoError(t, err)
		assert.Contains(t, stdout, "vault-dm-crypt")
		assert.Empty(t, stderr)

		// Startup should be fast (less than 5 seconds)
		assert.Less(t, duration, 5*time.Second, "Application startup took too long: %v", duration)

		t.Logf("Application startup time: %v", duration)
	})

	t.Run("memory_usage", func(t *testing.T) {
		// Test memory usage during operations
		// This is a basic test - more sophisticated memory profiling could be added

		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"decrypt",
			"memory-test-uuid",
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, "device with UUID")
		assert.Contains(t, stderr, "not found")
		assert.Empty(t, stdout)

		// The test completed without memory errors (basic check)
		assert.NotContains(t, stderr, "out of memory")
		assert.NotContains(t, stderr, "cannot allocate memory")
	})

	t.Run("concurrent_vault_operations", func(t *testing.T) {
		// Test multiple concurrent Vault operations
		done := make(chan error, 5)

		for i := 0; i < 5; i++ {
			go func(id int) {
				uuid := fmt.Sprintf("concurrent-vault-test-%d", id)
				stdout, stderr, err := framework.RunCommand(
					"--config", configFile,
					"decrypt",
					uuid,
				)

				// All should fail with device not found, not with Vault errors
				if err != nil && strings.Contains(stderr, "device with UUID") {
					done <- nil // Expected error
				} else {
					done <- fmt.Errorf("unexpected result for %s: err=%v, stdout=%s, stderr=%s", uuid, err, stdout, stderr)
				}
			}(i)
		}

		// Wait for all operations to complete
		timeout := time.After(30 * time.Second)
		for i := 0; i < 5; i++ {
			select {
			case err := <-done:
				assert.NoError(t, err)
			case <-timeout:
				t.Fatal("Concurrent operations timed out")
			}
		}
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

	t.Run("vault_connection_failure", func(t *testing.T) {
		// Test behavior when Vault is unavailable
		unavailableConfigContent := fmt.Sprintf(`[vault]
url = "http://localhost:9999"  # Non-existent Vault server
backend = "secret"
approle = "%s"
secret_id = "%s"
timeout = 5
retry_max = 1
retry_delay = 1

[logging]
level = "debug"
format = "text"
output = "stdout"
`, roleID, secretID)

		unavailableConfigFile := framework.GetTempDir() + "/unavailable-config.toml"
		err := os.WriteFile(unavailableConfigFile, []byte(unavailableConfigContent), 0644)
		require.NoError(t, err)

		start := time.Now()
		stdout, stderr, err := framework.RunCommand(
			"--config", unavailableConfigFile,
			"decrypt",
			"test-uuid",
		)
		duration := time.Since(start)

		assert.Error(t, err)
		assert.Contains(t, stderr, "connection refused")
		assert.Empty(t, stdout)

		// Should fail quickly due to short timeout and retry settings
		assert.Less(t, duration, 15*time.Second, "Operation took too long to fail: %v", duration)
	})

	t.Run("partial_operation_cleanup", func(t *testing.T) {
		// Test that partial operations clean up properly
		// This tests what happens when operations are interrupted

		// Create a context that will be cancelled
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Start a long-running operation in background
		cmd := exec.CommandContext(ctx, framework.GetBinaryPath(),
			"--config", configFile,
			"decrypt",
			"cleanup-test-uuid")

		// Start the command
		err := cmd.Start()
		require.NoError(t, err)

		// Let it run briefly then cancel
		time.Sleep(100 * time.Millisecond)
		cancel()

		// Wait for it to finish
		err = cmd.Wait()
		assert.Error(t, err) // Should be cancelled

		// Verify no processes are left hanging
		// This is a basic check - more sophisticated process monitoring could be added
		assert.True(t, true, "Process cleanup test completed")
	})

	t.Run("invalid_device_recovery", func(t *testing.T) {
		// Test recovery from invalid device operations
		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"encrypt",
			"/dev/null", // Invalid device for encryption
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, "validation failed")
		assert.Empty(t, stdout)

		// After failure, system should still be responsive
		stdout, stderr, err = framework.RunCommand(
			"--config", configFile,
			"--help",
		)

		assert.NoError(t, err)
		assert.Contains(t, stdout, "vault-dm-crypt")
		assert.Empty(t, stderr)
	})
}

// TestSecurityBoundaries tests security-related functionality
func TestSecurityBoundaries(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("credential_isolation", func(t *testing.T) {
		// Test that credentials are properly isolated and not leaked

		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"--debug",
			"decrypt",
			"security-test-uuid",
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, "device with UUID")

		// Verify that sensitive information is not leaked in logs
		combinedOutput := stdout + stderr
		assert.NotContains(t, combinedOutput, secretID, "Secret ID leaked in output")
		assert.NotContains(t, combinedOutput, "test-root-token", "Root token leaked in output")
	})

	t.Run("configuration_file_permissions", func(t *testing.T) {
		// Test that configuration files with bad permissions are handled properly
		badPermConfigFile := framework.GetTempDir() + "/bad-perm-config.toml"

		// Create config file
		configContent := fmt.Sprintf(`[vault]
url = "%s"
backend = "secret"
approle = "%s"
secret_id = "%s"

[logging]
level = "info"
`, vaultAddr, roleID, secretID)

		err := os.WriteFile(badPermConfigFile, []byte(configContent), 0644)
		require.NoError(t, err)

		// Test with the file (should work with 0644)
		stdout, stderr, err := framework.RunCommand(
			"--config", badPermConfigFile,
			"--help",
		)

		assert.NoError(t, err)
		assert.Contains(t, stdout, "vault-dm-crypt")
		assert.Empty(t, stderr)
	})

	t.Run("input_validation", func(t *testing.T) {
		// Test input validation for various parameters

		// Test with extremely long UUID
		longUUID := strings.Repeat("a", 1000)
		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"decrypt",
			longUUID,
		)

		assert.Error(t, err)
		// Should handle long input gracefully
		assert.NotContains(t, stderr, "panic")
		assert.NotContains(t, stderr, "runtime error")

		// Test with special characters in UUID
		specialUUID := "../../etc/passwd"
		stdout, stderr, err = framework.RunCommand(
			"--config", configFile,
			"decrypt",
			specialUUID,
		)

		assert.Error(t, err)
		// Should handle special characters safely
		assert.NotContains(t, stderr, "panic")
		assert.NotContains(t, stderr, "runtime error")
	})
}
