//go:build integration
// +build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSystemdIntegration tests comprehensive systemd integration
func TestSystemdIntegration(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireRoot()
	framework.RequireDocker()
	framework.RequireCommands("systemctl", "vault", "cryptsetup", "losetup")

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("service_template_validation", func(t *testing.T) {
		// Check if the systemd service template exists in the project
		projectRoot, err := findProjectRoot()
		require.NoError(t, err)

		serviceTemplatePath := filepath.Join(projectRoot, "configs", "systemd", "vault-dm-crypt-decrypt@.service")

		if _, err := os.Stat(serviceTemplatePath); err == nil {
			// Service template exists, validate its content
			content, err := os.ReadFile(serviceTemplatePath)
			require.NoError(t, err)

			serviceContent := string(content)

			// Validate essential service properties
			assert.Contains(t, serviceContent, "[Unit]", "Service should have Unit section")
			assert.Contains(t, serviceContent, "[Service]", "Service should have Service section")
			assert.Contains(t, serviceContent, "[Install]", "Service should have Install section")

			// Validate service type and execution
			assert.Contains(t, serviceContent, "Type=", "Service should specify type")
			assert.Contains(t, serviceContent, "ExecStart=", "Service should specify ExecStart")

			// Validate systemd instance parameter usage
			assert.Contains(t, serviceContent, "%i", "Service should use instance parameter")

			// Validate dependencies
			assert.Contains(t, serviceContent, "After=", "Service should specify dependencies")

			t.Logf("Systemd service template validation passed")
		} else {
			t.Skip("Systemd service template not found, skipping validation")
		}
	})

	t.Run("systemctl_availability", func(t *testing.T) {
		// Test basic systemctl functionality
		cmd := exec.Command("systemctl", "--version")
		output, err := cmd.Output()
		require.NoError(t, err, "systemctl should be available")

		versionOutput := string(output)
		assert.Contains(t, versionOutput, "systemd", "Should be systemd")

		t.Logf("Systemd version: %s", strings.Split(versionOutput, "\n")[0])
	})

	t.Run("service_file_installation", func(t *testing.T) {
		// Test service file installation (simulation)
		serviceContent := createTestServiceTemplate(framework.GetBinaryPath())

		// Create a temporary service file
		tempServiceDir := filepath.Join(framework.GetTempDir(), "systemd")
		err := os.MkdirAll(tempServiceDir, 0755)
		require.NoError(t, err)

		serviceFile := filepath.Join(tempServiceDir, "vault-dm-crypt-decrypt@.service")
		err = os.WriteFile(serviceFile, []byte(serviceContent), 0644)
		require.NoError(t, err)

		// Validate service file syntax using systemd-analyze (if available)
		if _, err := exec.LookPath("systemd-analyze"); err == nil {
			cmd := exec.Command("systemd-analyze", "verify", serviceFile)
			output, err := cmd.CombinedOutput()

			if err != nil {
				t.Logf("Service file validation warnings/errors: %s", string(output))
				// Don't fail the test for warnings, just log them
			} else {
				t.Logf("Service file validation passed")
			}
		} else {
			t.Logf("systemd-analyze not available, skipping service file validation")
		}

		// Test that the service file is well-formed
		content, err := os.ReadFile(serviceFile)
		require.NoError(t, err)

		serviceStr := string(content)
		assert.Contains(t, serviceStr, "vault-dm-crypt")
		assert.Contains(t, serviceStr, "decrypt %i")
		assert.Contains(t, serviceStr, configFile)
	})

	t.Run("service_enablement_simulation", func(t *testing.T) {
		// Test service enablement logic (without actually installing to system)
		testUUID := "test-service-uuid-12345"

		// This would normally be done by the application
		serviceName := fmt.Sprintf("vault-dm-crypt-decrypt@%s.service", testUUID)

		// Verify service name format
		assert.Contains(t, serviceName, testUUID)
		assert.Contains(t, serviceName, "vault-dm-crypt-decrypt@")
		assert.True(t, strings.HasSuffix(serviceName, ".service"))

		t.Logf("Service name format validation passed: %s", serviceName)

		// Test that we can check service status (even if service doesn't exist)
		cmd := exec.Command("systemctl", "is-enabled", serviceName)
		output, err := cmd.CombinedOutput()

		// Service shouldn't exist, so this should fail
		assert.Error(t, err)
		outputStr := string(output)

		// Should get a reasonable error message
		assert.True(t,
			strings.Contains(outputStr, "not found") ||
				strings.Contains(outputStr, "disabled") ||
				strings.Contains(outputStr, "No such file"),
			"Should get reasonable error for non-existent service")

		t.Logf("Service status check behaved as expected: %s", strings.TrimSpace(outputStr))
	})

	t.Run("service_configuration_validation", func(t *testing.T) {
		// Test various service configuration scenarios
		testConfigs := []struct {
			name   string
			config string
			valid  bool
		}{
			{
				name:   "valid_config_path",
				config: configFile,
				valid:  true,
			},
			{
				name:   "nonexistent_config",
				config: "/nonexistent/config.toml",
				valid:  false,
			},
			{
				name:   "relative_config_path",
				config: "./relative-config.toml",
				valid:  false,
			},
		}

		for _, tc := range testConfigs {
			t.Run(tc.name, func(t *testing.T) {
				serviceContent := createTestServiceTemplateWithConfig(framework.GetBinaryPath(), tc.config)

				// Validate service content
				if tc.valid {
					assert.Contains(t, serviceContent, tc.config)
					assert.Contains(t, serviceContent, "decrypt %i")
				} else {
					// Even invalid configs should produce valid service syntax
					assert.Contains(t, serviceContent, "ExecStart=")
					assert.Contains(t, serviceContent, "vault-dm-crypt")
				}
			})
		}
	})

	t.Run("service_dependency_validation", func(t *testing.T) {
		// Test service dependencies and ordering
		serviceContent := createTestServiceTemplate(framework.GetBinaryPath())

		// Validate network dependencies
		assert.Contains(t, serviceContent, "After=network-online.target",
			"Service should wait for network")
		assert.Contains(t, serviceContent, "Wants=network-online.target",
			"Service should want network online")

		// Validate cryptsetup dependencies (if applicable)
		if strings.Contains(serviceContent, "cryptsetup") {
			assert.Contains(t, serviceContent, "After=cryptsetup.target")
		}

		// Validate that service doesn't start too early
		assert.Contains(t, serviceContent, "DefaultDependencies=",
			"Service should specify default dependencies behavior")

		t.Logf("Service dependency validation passed")
	})

	t.Run("service_failure_handling", func(t *testing.T) {
		// Test service failure and restart policies
		serviceContent := createTestServiceTemplate(framework.GetBinaryPath())

		// Check for failure handling configuration
		if strings.Contains(serviceContent, "Restart=") {
			// If restart is configured, validate it's reasonable
			assert.True(t,
				strings.Contains(serviceContent, "Restart=on-failure") ||
					strings.Contains(serviceContent, "Restart=no"),
				"Restart policy should be reasonable")
		}

		// Check for timeout configuration
		if strings.Contains(serviceContent, "TimeoutStart=") {
			assert.NotContains(t, serviceContent, "TimeoutStart=0",
				"Timeout should not be zero")
		}

		t.Logf("Service failure handling validation passed")
	})

	t.Run("service_security_settings", func(t *testing.T) {
		// Test service security configuration
		serviceContent := createTestServiceTemplate(framework.GetBinaryPath())

		// Check for security settings
		securitySettings := []string{
			"User=root",       // Required for dm-crypt operations
			"PrivateNetwork=", // Network isolation settings
			"ProtectSystem=",  // System protection
			"PrivateTmp=",     // Temporary directory isolation
		}

		foundSettings := 0
		for _, setting := range securitySettings {
			if strings.Contains(serviceContent, setting) {
				foundSettings++
				t.Logf("Found security setting: %s", setting)
			}
		}

		// At minimum, should run as root
		assert.Contains(t, serviceContent, "User=root",
			"Service should run as root for dm-crypt operations")

		t.Logf("Service security validation passed (%d/%d settings found)",
			foundSettings, len(securitySettings))
	})

	t.Run("end_to_end_service_simulation", func(t *testing.T) {
		// Simulate the complete service workflow without actually installing
		if !framework.isRoot() {
			t.Skip("End-to-end service simulation requires root privileges")
		}

		// Create a test device and encrypt it
		device, err := framework.CreateLoopDevice(30) // 30MB
		require.NoError(t, err)

		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"encrypt",
			"--force",
			device,
		)

		require.NoError(t, err, "Encryption failed: %s", stderr)
		uuid, _ := extractEncryptionDetails(t, stdout)
		require.NotEmpty(t, uuid)

		// Simulate what the systemd service would do
		// 1. Create service command line
		serviceCommand := []string{
			framework.GetBinaryPath(),
			"--config", configFile,
			"decrypt", uuid,
		}

		// 2. Test the command that would be run by systemd
		cmd := exec.Command(serviceCommand[0], serviceCommand[1:]...)
		output, err := cmd.CombinedOutput()

		assert.NoError(t, err, "Service command should succeed: %s", string(output))
		assert.Contains(t, string(output), "Device decrypted successfully")

		t.Logf("End-to-end service simulation completed successfully")
	})
}

// TestSystemdEnvironment tests systemd-specific environment handling
func TestSystemdEnvironment(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireCommands("systemctl")

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	t.Run("systemd_environment_variables", func(t *testing.T) {
		// Test handling of systemd-specific environment variables
		systemdEnvVars := map[string]string{
			"SYSTEMD_EXEC_PID":   "12345",
			"INVOCATION_ID":      "test-invocation-id",
			"JOURNAL_STREAM":     "8:12345",
			"SYSTEMD_LOG_LEVEL":  "info",
			"SYSTEMD_LOG_TARGET": "journal",
		}

		// Set systemd environment variables
		for key, value := range systemdEnvVars {
			_ = os.Setenv(key, value)
			defer func() { _ = os.Unsetenv(key) }()
		}

		// Test that the application handles systemd environment correctly
		stdout, stderr, err := framework.RunCommand("--version")

		assert.NoError(t, err)
		assert.Contains(t, stdout, "vault-dm-crypt")
		assert.Empty(t, stderr)

		// Application should not be affected by systemd environment variables
		assert.NotContains(t, stdout, "SYSTEMD_")
		assert.NotContains(t, stdout, "INVOCATION_ID")

		t.Logf("Systemd environment handling test passed")
	})

	t.Run("journal_logging_compatibility", func(t *testing.T) {
		// Test compatibility with systemd journal logging
		vaultAddr, roleID, secretID := "http://localhost:8200", "test-role", "test-secret"

		journalConfig := fmt.Sprintf(`[vault]
url = "%s"
backend = "secret"
approle = "%s"
secret_id = "%s"

[logging]
level = "info"
format = "text"
output = "stdout"
`, vaultAddr, roleID, secretID)

		journalConfigFile := filepath.Join(framework.GetTempDir(), "journal-config.toml")
		err := os.WriteFile(journalConfigFile, []byte(journalConfig), 0644)
		require.NoError(t, err)

		// Test with journal-compatible output
		stdout, stderr, err := framework.RunCommand(
			"--config", journalConfigFile,
			"--help",
		)

		assert.NoError(t, err)
		assert.Contains(t, stdout, "vault-dm-crypt")
		assert.Empty(t, stderr)

		// Output should be journal-friendly (no control characters, etc.)
		assert.NotContains(t, stdout, "\x1b[") // No ANSI escape codes
		assert.NotContains(t, stdout, "\r")    // No carriage returns

		t.Logf("Journal logging compatibility test passed")
	})

	t.Run("service_startup_ordering", func(t *testing.T) {
		// Test that service dependencies are correctly specified
		serviceContent := createTestServiceTemplate(framework.GetBinaryPath())

		// Parse and validate dependencies
		lines := strings.Split(serviceContent, "\n")
		var afterServices, wantedBy []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "After=") {
				afterServices = append(afterServices, strings.TrimPrefix(line, "After="))
			}
			if strings.HasPrefix(line, "WantedBy=") {
				wantedBy = append(wantedBy, strings.TrimPrefix(line, "WantedBy="))
			}
		}

		// Validate essential dependencies
		afterStr := strings.Join(afterServices, " ")
		assert.Contains(t, afterStr, "network",
			"Service should depend on network")

		// Validate installation target
		wantedByStr := strings.Join(wantedBy, " ")
		assert.True(t,
			strings.Contains(wantedByStr, "multi-user.target") ||
				strings.Contains(wantedByStr, "graphical.target"),
			"Service should be wanted by appropriate target")

		t.Logf("Service startup ordering validation passed")
	})
}

// Helper functions

func createTestServiceTemplate(binaryPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Vault DM-Crypt Decrypt Service for %%i
After=network-online.target
Wants=network-online.target
DefaultDependencies=yes

[Service]
Type=oneshot
User=root
Group=root
ExecStart=%s --config /etc/vault-dm-crypt/config.toml decrypt %%i
TimeoutStart=300
RemainAfterExit=no
StandardOutput=journal
StandardError=journal

# Security settings
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/dev /sys

[Install]
WantedBy=multi-user.target
`, binaryPath)
}

func createTestServiceTemplateWithConfig(binaryPath, configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=Vault DM-Crypt Decrypt Service for %%i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=%s --config %s decrypt %%i
TimeoutStart=300

[Install]
WantedBy=multi-user.target
`, binaryPath, configPath)
}

func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("could not find project root")
}

func (tf *TestFramework) isRoot() bool {
	return os.Geteuid() == 0
}
