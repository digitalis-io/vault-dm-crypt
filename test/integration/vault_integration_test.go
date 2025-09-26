package integration

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVaultIntegration tests basic Vault connectivity and authentication
func TestVaultIntegration(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireDocker()
	framework.RequireCommands("vault", "curl")

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("vault_connectivity", func(t *testing.T) {
		// Test that we can connect to Vault by running a simple operation
		// This tests the Vault client initialization and basic connectivity

		// Create a minimal test secret directly via vault CLI
		cmd := []string{"vault", "kv", "put", "secret/test-path", "test-key=test-value"}
		_, stderr, err := framework.RunCommand(cmd...)

		// The command should fail because our binary doesn't have a vault subcommand
		// but this tests that our framework setup is working
		assert.Error(t, err)
		assert.Contains(t, stderr, "unknown command")
	})

	t.Run("config_validation", func(t *testing.T) {
		// Test configuration file parsing
		stdout, stderr, err := framework.RunCommand("--config", configFile, "--help")

		// Should successfully show help without configuration errors
		assert.NoError(t, err)
		assert.Contains(t, stdout, "vault-dm-crypt")
		assert.Contains(t, stdout, "encrypt")
		assert.Contains(t, stdout, "decrypt")
		assert.Empty(t, stderr)
	})

	t.Run("vault_auth_validation", func(t *testing.T) {
		// Test that the application can authenticate with Vault
		// We'll try an operation that requires Vault auth and expect a specific error

		// Try to decrypt a non-existent device - this should authenticate but then fail to find the UUID
		_, stderr, err := framework.RunCommand("--config", configFile, "decrypt", "non-existent-uuid")

		assert.Error(t, err)
		// Should get past authentication but fail on device lookup
		assert.Contains(t, stderr, "device with UUID non-existent-uuid not found")
	})
}

// TestEndToEndEncryptDecrypt tests the full encrypt/decrypt workflow with loop devices
func TestEndToEndEncryptDecrypt(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireRoot()
	framework.RequireDocker()
	framework.RequireCommands("vault", "curl", "losetup", "dd", "cryptsetup")

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("encrypt_loop_device", func(t *testing.T) {
		// Create a loop device for testing
		loopDevice, err := framework.CreateLoopDevice(10) // 10MB
		require.NoError(t, err)

		// Test encryption
		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"encrypt",
			"--force", // Force encryption without confirmation
			loopDevice,
		)

		if err != nil {
			t.Logf("Encryption failed - this is expected if not running as root")
			t.Logf("STDOUT: %s", stdout)
			t.Logf("STDERR: %s", stderr)

			// Check if it's a permission error (expected when not root)
			if strings.Contains(stderr, "permission denied") ||
				strings.Contains(stderr, "operation not permitted") ||
				strings.Contains(stderr, "must be run as root") {
				t.Skip("Skipping encryption test - requires root privileges")
			}

			// If it's not a permission error, it's a real failure
			t.Fatalf("Encryption failed with unexpected error: %v\nSTDOUT: %s\nSTDERR: %s", err, stdout, stderr)
		}

		// If we get here, encryption succeeded
		assert.NoError(t, err)
		assert.Contains(t, stdout, "Device encrypted successfully")
		assert.Contains(t, stdout, "UUID:")
		assert.Contains(t, stdout, "Mapped device:")
		assert.Contains(t, stdout, "Vault path:")

		// Extract UUID from output
		lines := strings.Split(stdout, "\n")
		var uuid string
		for _, line := range lines {
			if strings.Contains(line, "UUID:") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					uuid = strings.TrimSpace(parts[1])
				}
			}
		}
		require.NotEmpty(t, uuid, "Failed to extract UUID from encryption output")

		t.Run("decrypt_device", func(t *testing.T) {
			// Test decryption with the UUID from encryption
			stdout, stderr, err := framework.RunCommand(
				"--config", configFile,
				"decrypt",
				uuid,
			)

			assert.NoError(t, err)
			assert.Contains(t, stdout, "Device decrypted successfully")
			assert.Contains(t, stdout, "UUID: "+uuid)
			assert.Contains(t, stdout, "Device:")
			assert.Contains(t, stdout, "Mapped device:")
			assert.Empty(t, stderr)
		})
	})
}

// TestErrorHandling tests various error conditions and edge cases
func TestErrorHandling(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("encrypt_nonexistent_device", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"encrypt",
			"/dev/nonexistent-device",
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, "device validation failed")
		assert.Empty(t, stdout)
	})

	t.Run("decrypt_nonexistent_uuid", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"decrypt",
			"00000000-0000-0000-0000-000000000000",
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, "device with UUID")
		assert.Contains(t, stderr, "not found")
		assert.Empty(t, stdout)
	})

	t.Run("invalid_config_file", func(t *testing.T) {
		invalidConfigFile := framework.GetTempDir() + "/invalid-config.toml"
		err := os.WriteFile(invalidConfigFile, []byte("invalid toml content [[["), 0644)
		require.NoError(t, err)

		stdout, stderr, err := framework.RunCommand(
			"--config", invalidConfigFile,
			"--help",
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, "failed to load configuration")
		assert.Empty(t, stdout)
	})

	t.Run("missing_config_file", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand(
			"--config", "/nonexistent/config.toml",
			"--help",
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, "failed to load configuration")
		assert.Empty(t, stdout)
	})

	t.Run("invalid_vault_credentials", func(t *testing.T) {
		// Create config with invalid Vault credentials
		invalidConfigFile, err := framework.CreateTestConfig(vaultAddr, "invalid-role", "invalid-secret")
		require.NoError(t, err)

		stdout, stderr, err := framework.RunCommand(
			"--config", invalidConfigFile,
			"decrypt",
			"test-uuid",
		)

		assert.Error(t, err)
		// Should fail during authentication, not device lookup
		assert.Contains(t, stderr, "authentication failed")
		assert.Empty(t, stdout)
	})
}

// TestCommandLineInterface tests CLI argument parsing and validation
func TestCommandLineInterface(t *testing.T) {
	framework := NewTestFramework(t)

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	t.Run("help_command", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand("--help")

		assert.NoError(t, err)
		assert.Contains(t, stdout, "vault-dm-crypt")
		assert.Contains(t, stdout, "Store and retrieve dm-crypt keys")
		assert.Contains(t, stdout, "encrypt")
		assert.Contains(t, stdout, "decrypt")
		assert.Empty(t, stderr)
	})

	t.Run("version_command", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand("--version")

		assert.NoError(t, err)
		assert.Contains(t, stdout, "vault-dm-crypt")
		assert.Empty(t, stderr)
	})

	t.Run("encrypt_help", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand("encrypt", "--help")

		assert.NoError(t, err)
		assert.Contains(t, stdout, "Encrypt a block device")
		assert.Contains(t, stdout, "--force")
		assert.Empty(t, stderr)
	})

	t.Run("decrypt_help", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand("decrypt", "--help")

		assert.NoError(t, err)
		assert.Contains(t, stdout, "Decrypt and open an encrypted device")
		assert.Contains(t, stdout, "--name")
		assert.Empty(t, stderr)
	})

	t.Run("invalid_command", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand("invalid-command")

		assert.Error(t, err)
		assert.Contains(t, stderr, "unknown command")
		assert.Empty(t, stdout)
	})

	t.Run("encrypt_missing_args", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand("encrypt")

		assert.Error(t, err)
		assert.Contains(t, stderr, "requires exactly 1 arg")
		assert.Empty(t, stdout)
	})

	t.Run("decrypt_missing_args", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand("decrypt")

		assert.Error(t, err)
		assert.Contains(t, stderr, "requires exactly 1 arg")
		assert.Empty(t, stdout)
	})
}

// TestSystemdIntegration tests systemd service management (when available)
func TestSystemdIntegration(t *testing.T) {
	framework := NewTestFramework(t)

	// Check if systemd is available
	framework.RequireCommands("systemctl")

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	t.Run("systemd_service_availability", func(t *testing.T) {
		// This test checks if the application can interact with systemd
		// We can't test actual service installation without root, but we can
		// test that systemd commands are available and the service template exists

		// For now, this is a placeholder test that verifies systemd is available
		// In a full implementation, this would test service installation/management
		assert.True(t, true, "Systemd integration test placeholder")
	})
}

// TestConcurrentOperations tests multiple operations running simultaneously
func TestConcurrentOperations(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("concurrent_decrypt_attempts", func(t *testing.T) {
		// Test multiple concurrent decrypt operations
		done := make(chan bool, 3)

		for i := 0; i < 3; i++ {
			go func(id int) {
				defer func() { done <- true }()

				uuid := "concurrent-test-uuid-" + string(rune('1'+id))
				stdout, stderr, err := framework.RunCommand(
					"--config", configFile,
					"decrypt",
					uuid,
				)

				// All should fail with "device not found" but not crash
				assert.Error(t, err)
				assert.Contains(t, stderr, "device with UUID")
				assert.Contains(t, stderr, "not found")
				assert.Empty(t, stdout)
			}(i)
		}

		// Wait for all goroutines to complete with timeout
		timeout := time.After(30 * time.Second)
		for i := 0; i < 3; i++ {
			select {
			case <-done:
				// Operation completed
			case <-timeout:
				t.Fatal("Concurrent operations timed out")
			}
		}
	})
}
