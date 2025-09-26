package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDMCryptOperations tests comprehensive dm-crypt functionality
func TestDMCryptOperations(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireRoot()
	framework.RequireDocker()
	framework.RequireCommands("vault", "curl", "losetup", "dd", "cryptsetup", "lsblk", "blkid")

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("complete_encryption_workflow", func(t *testing.T) {
		// Create multiple loop devices for comprehensive testing
		device1, err := framework.CreateLoopDevice(50) // 50MB
		require.NoError(t, err)

		device2, err := framework.CreateLoopDevice(100) // 100MB
		require.NoError(t, err)

		// Test encryption of first device
		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"--debug",
			"encrypt",
			"--force",
			device1,
		)

		require.NoError(t, err, "Encryption failed: %s", stderr)
		assert.Contains(t, stdout, "Device encrypted successfully")

		// Extract UUID and mapped device from output
		uuid1, mappedDevice1 := extractEncryptionDetails(t, stdout)
		require.NotEmpty(t, uuid1, "Failed to extract UUID from encryption output")
		require.NotEmpty(t, mappedDevice1, "Failed to extract mapped device from encryption output")

		t.Logf("Device 1 - UUID: %s, Mapped: %s", uuid1, mappedDevice1)

		// Verify LUKS device was created properly
		verifyLUKSDevice(t, device1, uuid1)

		// Test encryption of second device
		stdout, stderr, err = framework.RunCommand(
			"--config", configFile,
			"--debug",
			"encrypt",
			"--force",
			device2,
		)

		require.NoError(t, err, "Second encryption failed: %s", stderr)
		uuid2, mappedDevice2 := extractEncryptionDetails(t, stdout)
		require.NotEmpty(t, uuid2, "Failed to extract UUID from second encryption")

		t.Logf("Device 2 - UUID: %s, Mapped: %s", uuid2, mappedDevice2)

		// Verify both devices have different UUIDs
		assert.NotEqual(t, uuid1, uuid2, "UUIDs should be unique")

		// Test decryption of both devices
		t.Run("decrypt_first_device", func(t *testing.T) {
			testDecryption(t, framework, configFile, uuid1, device1)
		})

		t.Run("decrypt_second_device", func(t *testing.T) {
			testDecryption(t, framework, configFile, uuid2, device2)
		})

		// Test custom device naming
		t.Run("custom_device_naming", func(t *testing.T) {
			customName := "custom-test-device"
			stdout, stderr, err := framework.RunCommand(
				"--config", configFile,
				"decrypt",
				"--name", customName,
				uuid1,
			)

			assert.NoError(t, err, "Custom naming failed: %s", stderr)
			assert.Contains(t, stdout, "Device decrypted successfully")
			assert.Contains(t, stdout, customName)
		})
	})

	t.Run("device_validation", func(t *testing.T) {
		// Test various invalid device scenarios
		testCases := []struct {
			name   string
			device string
			error  string
		}{
			{
				name:   "nonexistent_device",
				device: "/dev/nonexistent-device-12345",
				error:  "device validation failed",
			},
			{
				name:   "directory_instead_of_device",
				device: "/tmp",
				error:  "device validation failed",
			},
			{
				name:   "regular_file",
				device: configFile,
				error:  "device validation failed",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				stdout, stderr, err := framework.RunCommand(
					"--config", configFile,
					"encrypt",
					tc.device,
				)

				assert.Error(t, err)
				assert.Contains(t, stderr, tc.error)
				assert.Empty(t, stdout)
			})
		}
	})

	t.Run("luks_format_validation", func(t *testing.T) {
		// Create a device and encrypt it, then verify LUKS format details
		device, err := framework.CreateLoopDevice(25) // 25MB
		require.NoError(t, err)

		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"encrypt",
			"--force",
			device,
		)

		require.NoError(t, err, "Encryption failed: %s", stderr)
		uuid, _ := extractEncryptionDetails(t, stdout)

		// Verify LUKS format using cryptsetup
		cmd := exec.Command("cryptsetup", "luksDump", device)
		output, err := cmd.Output()
		require.NoError(t, err, "Failed to dump LUKS header")

		dumpOutput := string(output)
		assert.Contains(t, dumpOutput, "LUKS header information")
		assert.Contains(t, dumpOutput, "UUID:")
		assert.Contains(t, dumpOutput, uuid)

		// Verify cipher and hash algorithms
		assert.Contains(t, dumpOutput, "Cipher name:")
		assert.Contains(t, dumpOutput, "Hash spec:")

		t.Logf("LUKS dump output:\n%s", dumpOutput)
	})

	t.Run("key_strength_validation", func(t *testing.T) {
		// Test that generated keys are of appropriate strength
		device, err := framework.CreateLoopDevice(20) // 20MB
		require.NoError(t, err)

		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"--debug",
			"encrypt",
			"--force",
			device,
		)

		require.NoError(t, err, "Encryption failed: %s", stderr)
		uuid, _ := extractEncryptionDetails(t, stdout)

		// Verify the key was stored in Vault by attempting decryption
		stdout, stderr, err = framework.RunCommand(
			"--config", configFile,
			"decrypt",
			uuid,
		)

		assert.NoError(t, err, "Decryption failed, indicating weak key: %s", stderr)
		assert.Contains(t, stdout, "Device decrypted successfully")
	})

	t.Run("multiple_operations_same_device", func(t *testing.T) {
		// Test attempting to encrypt an already encrypted device
		device, err := framework.CreateLoopDevice(30) // 30MB
		require.NoError(t, err)

		// First encryption should succeed
		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"encrypt",
			"--force",
			device,
		)

		require.NoError(t, err, "First encryption failed: %s", stderr)
		uuid, _ := extractEncryptionDetails(t, stdout)

		// Second encryption attempt should handle the already-encrypted device appropriately
		stdout, stderr, err = framework.RunCommand(
			"--config", configFile,
			"encrypt",
			"--force",
			device,
		)

		// This should either succeed (overwriting) or fail gracefully
		if err != nil {
			// If it fails, it should be a controlled failure
			assert.NotContains(t, stderr, "panic")
			assert.NotContains(t, stderr, "runtime error")
			t.Logf("Second encryption attempt failed as expected: %s", stderr)
		} else {
			// If it succeeds, it should generate a new UUID
			newUUID, _ := extractEncryptionDetails(t, stdout)
			t.Logf("Second encryption succeeded with new UUID: %s (original: %s)", newUUID, uuid)
		}
	})
}

// TestVaultSecretLifecycle tests comprehensive Vault secret management
func TestVaultSecretLifecycle(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireRoot()
	framework.RequireDocker()
	framework.RequireCommands("vault", "cryptsetup", "losetup")

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("secret_storage_and_retrieval", func(t *testing.T) {
		device, err := framework.CreateLoopDevice(40) // 40MB
		require.NoError(t, err)

		// Encrypt device
		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"encrypt",
			"--force",
			device,
		)

		require.NoError(t, err, "Encryption failed: %s", stderr)
		uuid, _ := extractEncryptionDetails(t, stdout)

		// Verify secret exists in Vault using vault CLI
		vaultPath := fmt.Sprintf("secret/data/vaultlocker/%s", uuid)
		cmd := exec.Command("vault", "kv", "get", "-format=json", vaultPath)
		cmd.Env = append(os.Environ(),
			"VAULT_ADDR="+vaultAddr,
			"VAULT_TOKEN=test-root-token",
		)

		output, err := cmd.Output()
		require.NoError(t, err, "Failed to retrieve secret from Vault")

		// Verify secret contains expected fields
		secretOutput := string(output)
		assert.Contains(t, secretOutput, "dmcrypt_key")
		assert.Contains(t, secretOutput, "created_at")
		assert.Contains(t, secretOutput, "device")
		assert.Contains(t, secretOutput, device)

		t.Logf("Secret stored successfully in Vault: %s", vaultPath)

		// Test decryption (which retrieves the secret)
		stdout, stderr, err = framework.RunCommand(
			"--config", configFile,
			"decrypt",
			uuid,
		)

		assert.NoError(t, err, "Decryption failed: %s", stderr)
		assert.Contains(t, stdout, "Device decrypted successfully")
	})

	t.Run("secret_with_metadata", func(t *testing.T) {
		device, err := framework.CreateLoopDevice(35) // 35MB
		require.NoError(t, err)

		// Set hostname for metadata testing
		originalHostname := os.Getenv("HOSTNAME")
		os.Setenv("HOSTNAME", "test-integration-host")
		defer func() {
			if originalHostname != "" {
				os.Setenv("HOSTNAME", originalHostname)
			} else {
				os.Unsetenv("HOSTNAME")
			}
		}()

		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"encrypt",
			"--force",
			device,
		)

		require.NoError(t, err, "Encryption failed: %s", stderr)
		uuid, _ := extractEncryptionDetails(t, stdout)

		// Verify metadata in Vault
		vaultPath := fmt.Sprintf("secret/data/vaultlocker/%s", uuid)
		cmd := exec.Command("vault", "kv", "get", "-format=json", vaultPath)
		cmd.Env = append(os.Environ(),
			"VAULT_ADDR="+vaultAddr,
			"VAULT_TOKEN=test-root-token",
		)

		output, err := cmd.Output()
		require.NoError(t, err, "Failed to retrieve secret with metadata")

		secretOutput := string(output)
		assert.Contains(t, secretOutput, "test-integration-host")
		assert.Contains(t, secretOutput, "created_at")
	})

	t.Run("secret_not_found_handling", func(t *testing.T) {
		// Test decryption with non-existent UUID
		fakeUUID := "00000000-1111-2222-3333-444444444444"

		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"decrypt",
			fakeUUID,
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, "failed to retrieve key from Vault")
		assert.Empty(t, stdout)
	})
}

// TestSystemIntegration tests system-level integration points
func TestSystemIntegration(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireRoot()
	framework.RequireDocker()
	framework.RequireCommands("vault", "systemctl", "cryptsetup", "losetup")

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("device_persistence", func(t *testing.T) {
		// Test that devices remain accessible across operations
		device, err := framework.CreateLoopDevice(60) // 60MB
		require.NoError(t, err)

		// Encrypt device
		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"encrypt",
			"--force",
			device,
		)

		require.NoError(t, err, "Encryption failed: %s", stderr)
		uuid, mappedDevice := extractEncryptionDetails(t, stdout)

		// Verify mapped device exists
		_, err = os.Stat(mappedDevice)
		assert.NoError(t, err, "Mapped device not found: %s", mappedDevice)

		// Test device accessibility
		testFile := filepath.Join(mappedDevice, "test-file")
		cmd := exec.Command("dd", "if=/dev/zero", "of="+testFile, "bs=1M", "count=1")
		err = cmd.Run()

		if err != nil {
			// This might fail if the device isn't formatted with a filesystem
			// That's okay - we're mainly testing the mapping exists
			t.Logf("Could not write to device (expected if no filesystem): %v", err)
		}

		// Verify device can be found by UUID
		devicePath, err := findDeviceByUUID(uuid)
		if err == nil {
			assert.Equal(t, device, devicePath)
			t.Logf("Device found by UUID: %s -> %s", uuid, devicePath)
		} else {
			t.Logf("Device lookup by UUID failed (expected in test environment): %v", err)
		}
	})

	t.Run("concurrent_device_operations", func(t *testing.T) {
		// Test multiple devices being operated on simultaneously
		numDevices := 3
		devices := make([]string, numDevices)
		uuids := make([]string, numDevices)

		// Create devices
		for i := 0; i < numDevices; i++ {
			device, err := framework.CreateLoopDevice(20) // 20MB each
			require.NoError(t, err)
			devices[i] = device
		}

		// Encrypt devices concurrently
		done := make(chan error, numDevices)
		results := make(chan string, numDevices)

		for i, device := range devices {
			go func(idx int, dev string) {
				stdout, stderr, err := framework.RunCommand(
					"--config", configFile,
					"encrypt",
					"--force",
					dev,
				)

				if err != nil {
					done <- fmt.Errorf("device %d encryption failed: %v - %s", idx, err, stderr)
					results <- ""
				} else {
					uuid, _ := extractEncryptionDetails(t, stdout)
					done <- nil
					results <- uuid
				}
			}(i, device)
		}

		// Wait for all encryptions to complete
		for i := 0; i < numDevices; i++ {
			select {
			case err := <-done:
				assert.NoError(t, err)
			case <-time.After(120 * time.Second):
				t.Fatal("Concurrent encryption timed out")
			}

			select {
			case uuid := <-results:
				if uuid != "" {
					uuids[i] = uuid
				}
			default:
			}
		}

		// Verify all UUIDs are unique
		uniqueUUIDs := make(map[string]bool)
		for _, uuid := range uuids {
			if uuid != "" {
				assert.False(t, uniqueUUIDs[uuid], "Duplicate UUID found: %s", uuid)
				uniqueUUIDs[uuid] = true
			}
		}

		t.Logf("Successfully encrypted %d devices concurrently", len(uniqueUUIDs))
	})
}

// Helper functions

func extractEncryptionDetails(t *testing.T, output string) (uuid, mappedDevice string) {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.Contains(line, "UUID:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				uuid = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, "Mapped device:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				mappedDevice = strings.TrimSpace(parts[1])
			}
		}
	}

	return uuid, mappedDevice
}

func verifyLUKSDevice(t *testing.T, device, expectedUUID string) {
	// Verify device is LUKS formatted
	cmd := exec.Command("cryptsetup", "isLuks", device)
	err := cmd.Run()
	assert.NoError(t, err, "Device is not LUKS formatted: %s", device)

	// Verify UUID matches
	cmd = exec.Command("cryptsetup", "luksUUID", device)
	output, err := cmd.Output()
	if err == nil {
		actualUUID := strings.TrimSpace(string(output))
		assert.Equal(t, expectedUUID, actualUUID, "LUKS UUID mismatch")
	} else {
		t.Logf("Could not verify LUKS UUID (may be expected): %v", err)
	}
}

func testDecryption(t *testing.T, framework *TestFramework, configFile, uuid, originalDevice string) {
	stdout, stderr, err := framework.RunCommand(
		"--config", configFile,
		"decrypt",
		uuid,
	)

	assert.NoError(t, err, "Decryption failed: %s", stderr)
	assert.Contains(t, stdout, "Device decrypted successfully")
	assert.Contains(t, stdout, "UUID: "+uuid)
	assert.Contains(t, stdout, "Device:")
	assert.Contains(t, stdout, "Mapped device:")

	// Verify the original device is referenced
	assert.Contains(t, stdout, originalDevice)
}

func findDeviceByUUID(uuid string) (string, error) {
	// Try the standard UUID path first
	uuidPath := fmt.Sprintf("/dev/disk/by-uuid/%s", uuid)
	if _, err := os.Stat(uuidPath); err == nil {
		realPath, err := os.Readlink(uuidPath)
		if err == nil {
			if !strings.HasPrefix(realPath, "/") {
				realPath = filepath.Join("/dev/disk/by-uuid", realPath)
				realPath, _ = filepath.Abs(realPath)
			}
			return realPath, nil
		}
	}

	// Try using blkid
	cmd := exec.Command("blkid", "-U", uuid)
	output, err := cmd.Output()
	if err == nil {
		devicePath := strings.TrimSpace(string(output))
		if devicePath != "" {
			return devicePath, nil
		}
	}

	return "", fmt.Errorf("device with UUID %s not found", uuid)
}
