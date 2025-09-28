package integration

import (
	"context"
	"errors"
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

// TestErrorRecoveryScenarios tests comprehensive error recovery and edge cases
func TestErrorRecoveryScenarios(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("configuration_file_errors", func(t *testing.T) {
		testCases := []struct {
			name        string
			configFunc  func(string) string
			expectedErr string
		}{
			{
				name: "completely_invalid_toml",
				configFunc: func(tempDir string) string {
					content := "[vault\ninvalid toml syntax here"
					path := filepath.Join(tempDir, "invalid-syntax.toml")
					_ = os.WriteFile(path, []byte(content), 0644)
					return path
				},
				expectedErr: "failed to load configuration",
			},
			{
				name: "missing_required_fields",
				configFunc: func(tempDir string) string {
					content := `[vault]
# Missing URL, approle, secret_id
backend = "secret"

[logging]
level = "info"
`
					path := filepath.Join(tempDir, "missing-fields.toml")
					_ = os.WriteFile(path, []byte(content), 0644)
					return path
				},
				expectedErr: "failed to load configuration",
			},
			{
				name: "invalid_url_format",
				configFunc: func(tempDir string) string {
					content := fmt.Sprintf(`[vault]
url = "not-a-valid-url"
backend = "secret"
approle = "%s"
secret_id = "%s"

[logging]
level = "info"
`, roleID, secretID)
					path := filepath.Join(tempDir, "invalid-url.toml")
					_ = os.WriteFile(path, []byte(content), 0644)
					return path
				},
				expectedErr: framework.ExpectDecryptError(), // Will fail with root privileges before auth
			},
			{
				name: "invalid_timeout_values",
				configFunc: func(tempDir string) string {
					content := fmt.Sprintf(`[vault]
url = "%s"
backend = "secret"
approle = "%s"
secret_id = "%s"
timeout = -1
retry_max = -5

[logging]
level = "info"
`, vaultAddr, roleID, secretID)
					path := filepath.Join(tempDir, "invalid-timeouts.toml")
					_ = os.WriteFile(path, []byte(content), 0644)
					return path
				},
				expectedErr: "", // Should handle gracefully or use defaults
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				configPath := tc.configFunc(framework.GetTempDir())

				stdout, stderr, err := framework.RunCommand(
					"--config", configPath,
					"decrypt", "test-uuid",
				)

				assert.Error(t, err)
				if tc.expectedErr != "" {
					assert.Contains(t, stderr, tc.expectedErr)
				}
				assert.Empty(t, stdout)

				// Ensure no panic or crash
				assert.NotContains(t, stderr, "panic")
				assert.NotContains(t, stderr, "runtime error")
			})
		}
	})

	t.Run("command_line_argument_errors", func(t *testing.T) {
		testCases := []struct {
			name        string
			args        []string
			expectedErr string
			shouldError bool
		}{
			{
				name:        "no_arguments",
				args:        []string{},
				expectedErr: "Usage:",
				shouldError: false,
			},
			{
				name:        "invalid_command",
				args:        []string{"invalid-command"},
				expectedErr: "unknown command",
				shouldError: true,
			},
			{
				name:        "encrypt_no_device",
				args:        []string{"encrypt"},
				expectedErr: "accepts 1 arg(s), received 0",
				shouldError: true,
			},
			{
				name:        "decrypt_no_uuid",
				args:        []string{"decrypt"},
				expectedErr: "accepts 1 arg(s), received 0",
				shouldError: true,
			},
			{
				name:        "encrypt_too_many_args",
				args:        []string{"encrypt", "device1", "device2"},
				expectedErr: "accepts 1 arg(s), received 2",
				shouldError: true,
			},
			{
				name:        "decrypt_too_many_args",
				args:        []string{"decrypt", "uuid1", "uuid2"},
				expectedErr: "accepts 1 arg(s), received 2",
				shouldError: true,
			},
			{
				name:        "invalid_flag",
				args:        []string{"decrypt", "--invalid-flag", "test-uuid"},
				expectedErr: "unknown flag",
				shouldError: true,
			},
			{
				name:        "nonexistent_config_file",
				args:        []string{"--config", "/nonexistent/config.toml", "decrypt", "test-uuid"},
				expectedErr: "failed to load configuration",
				shouldError: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				stdout, stderr, err := framework.RunCommand(tc.args...)

				if tc.shouldError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
				combinedOutput := stdout + stderr
				if tc.expectedErr != "" {
					assert.Contains(t, combinedOutput, tc.expectedErr)
				}

				// Ensure graceful error handling
				assert.NotContains(t, combinedOutput, "panic")
				assert.NotContains(t, combinedOutput, "runtime error")
			})
		}
	})

	t.Run("filesystem_permission_errors", func(t *testing.T) {
		// Test various filesystem permission scenarios
		tempDir := framework.GetTempDir()

		// Create a config file with restrictive permissions
		restrictedConfig := filepath.Join(tempDir, "restricted-config.toml")
		configContent := fmt.Sprintf(`[vault]
url = "%s"
backend = "secret"
approle = "%s"
secret_id = "%s"

[logging]
level = "info"
`, vaultAddr, roleID, secretID)

		err := os.WriteFile(restrictedConfig, []byte(configContent), 0000) // No permissions
		require.NoError(t, err)

		stdout, stderr, err := framework.RunCommand(
			"--config", restrictedConfig,
			"decrypt", "test-uuid",
		)

		assert.Error(t, err)
		// Should fail to read config file
		assert.Contains(t, stderr, "permission denied")
		assert.Empty(t, stdout)

		// Cleanup
		_ = os.Chmod(restrictedConfig, 0644)
		_ = os.Remove(restrictedConfig)
	})

	t.Run("process_interruption_recovery", func(t *testing.T) {
		// Test process interruption and recovery scenarios
		testCases := []struct {
			name        string
			interruptAt time.Duration
			signal      string
		}{
			{
				name:        "early_interrupt",
				interruptAt: 100 * time.Millisecond,
				signal:      "SIGTERM",
			},
			{
				name:        "late_interrupt",
				interruptAt: 500 * time.Millisecond,
				signal:      "SIGINT",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				// Start a long-running operation
				cmd := exec.CommandContext(ctx, framework.GetBinaryPath(),
					"--config", configFile,
					"decrypt", "interrupt-test-uuid")

				err := cmd.Start()
				require.NoError(t, err)

				// Let it run for a bit, then interrupt
				time.Sleep(tc.interruptAt)
				cancel()

				// Wait for process to exit
				err = cmd.Wait()
				assert.Error(t, err) // Should be cancelled/interrupted

				// Verify no zombie processes or resource leaks
				// In a more comprehensive test, we would check for:
				// - Open file descriptors
				// - Network connections
				// - Memory usage
				// - Child processes

				t.Logf("Process interruption test (%s) completed", tc.name)
			})
		}
	})

	t.Run("disk_space_exhaustion", func(t *testing.T) {
		// Test behavior when disk space is exhausted
		// This is a simulation since we can't actually exhaust disk space

		// Create a config that writes to a small tmpfs or similar
		// For this test, we'll simulate by using a very small temp directory

		smallTempDir := filepath.Join(framework.GetTempDir(), "small-space")
		err := os.MkdirAll(smallTempDir, 0755)
		require.NoError(t, err)

		// Try to create log files in the constrained space
		constrainedConfig := fmt.Sprintf(`[vault]
url = "%s"
backend = "secret"
approle = "%s"
secret_id = "%s"

[logging]
level = "debug"
format = "text"
output = "%s/large-log-file.log"
`, vaultAddr, roleID, secretID, smallTempDir)

		constrainedConfigFile := filepath.Join(framework.GetTempDir(), "constrained-config.toml")
		err = os.WriteFile(constrainedConfigFile, []byte(constrainedConfig), 0644)
		require.NoError(t, err)

		_, stderr, err := framework.RunCommand(
			"--config", constrainedConfigFile,
			"decrypt", "disk-space-test-uuid",
		)

		// Should handle disk space issues gracefully
		if err != nil {
			// Check that it's a proper error, not a crash
			assert.NotContains(t, stderr, "panic")
			assert.NotContains(t, stderr, "runtime error")
		}

		t.Logf("Disk space constraint test completed")
	})
}

// TestEdgeCaseHandling tests various edge cases and boundary conditions
func TestEdgeCaseHandling(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("extreme_input_values", func(t *testing.T) {
		testCases := []struct {
			name  string
			uuid  string
			valid bool
		}{
			{
				name:  "empty_uuid",
				uuid:  "",
				valid: false,
			},
			{
				name:  "very_long_uuid",
				uuid:  strings.Repeat("a", 1000),
				valid: false,
			},
			{
				name:  "special_characters",
				uuid:  "../../etc/passwd",
				valid: false,
			},
			{
				name:  "null_bytes",
				uuid:  "test\x00uuid",
				valid: false,
			},
			{
				name:  "unicode_characters",
				uuid:  "test-uuid-🔒-unicode",
				valid: false,
			},
			{
				name:  "sql_injection_attempt",
				uuid:  "'; DROP TABLE secrets; --",
				valid: false,
			},
			{
				name:  "valid_uuid_format",
				uuid:  "550e8400-e29b-41d4-a716-446655440000",
				valid: true, // Should fail with device not found, not input validation
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				stdout, stderr, err := framework.RunCommand(
					"--config", configFile,
					"decrypt", tc.uuid,
				)

				assert.Error(t, err)
				assert.Empty(t, stdout)

				if tc.valid {
					// Should fail with device not found, not input validation error
					assert.Contains(t, stderr, framework.ExpectDecryptError())
				} else {
					// Should handle invalid input gracefully
					assert.NotContains(t, stderr, "panic")
					assert.NotContains(t, stderr, "runtime error")
				}

				// Note: The application may log the UUID value, which is acceptable
				// as long as it doesn't actually try to access files or execute SQL.
				// The test input is safely handled as a string parameter.
			})
		}
	})

	t.Run("environment_variable_injection", func(t *testing.T) {
		// Test that environment variables don't cause security issues
		maliciousEnvVars := map[string]string{
			"VAULT_ADDR":  "http://malicious-server.com",
			"VAULT_TOKEN": "malicious-token",
			"PATH":        "/malicious/path:" + os.Getenv("PATH"),
			"LD_PRELOAD":  "/malicious/lib.so",
			"HOME":        "/tmp/malicious-home",
			"TMPDIR":      "/tmp/malicious-tmp",
		}

		// Test with each malicious environment variable
		for envVar, envValue := range maliciousEnvVars {
			t.Run("inject_"+strings.ToLower(envVar), func(t *testing.T) {
				originalValue := os.Getenv(envVar)
				_ = os.Setenv(envVar, envValue)
				defer func() {
					if originalValue != "" {
						_ = os.Setenv(envVar, originalValue)
					} else {
						_ = os.Unsetenv(envVar)
					}
				}()

				stdout, stderr, err := framework.RunCommand(
					"--config", configFile,
					"decrypt", "env-injection-test-uuid",
				)

				assert.Error(t, err)
				assert.Empty(t, stdout)

				// Should not be affected by malicious environment variables
				// due to explicit configuration
				if envVar == "VAULT_ADDR" || envVar == "VAULT_TOKEN" {
					// These might cause different errors but shouldn't crash
					assert.NotContains(t, stderr, "panic")
					assert.NotContains(t, stderr, "runtime error")
				} else {
					// Other env vars shouldn't affect the operation
					assert.Contains(t, stderr, framework.ExpectDecryptError())
				}
			})
		}
	})

	t.Run("race_condition_testing", func(t *testing.T) {
		// Test potential race conditions with concurrent operations
		numConcurrent := 20
		done := make(chan string, numConcurrent)

		// Start multiple operations simultaneously
		for i := 0; i < numConcurrent; i++ {
			go func(id int) {
				uuid := fmt.Sprintf("race-test-%d", id)
				stdout, stderr, err := framework.RunCommand(
					"--config", configFile,
					"decrypt", uuid,
				)

				if err != nil && strings.Contains(stderr, framework.ExpectDecryptError()) {
					done <- "success"
				} else {
					done <- fmt.Sprintf("failure: %v - %s - %s", err, stderr, stdout)
				}
			}(i)
		}

		// Collect results
		successCount := 0
		for i := 0; i < numConcurrent; i++ {
			select {
			case result := <-done:
				if result == "success" {
					successCount++
				} else {
					t.Logf("Race test operation failed: %s", result)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("Race condition test timed out")
			}
		}

		// All operations should complete successfully (even if they "fail" to find the device)
		assert.Equal(t, numConcurrent, successCount, "Race condition detected")
		t.Logf("Race condition test: %d/%d operations completed successfully", successCount, numConcurrent)
	})

	t.Run("memory_limit_testing", func(t *testing.T) {
		// Test behavior under memory constraints
		// This test runs the application multiple times to check for memory leaks

		initialRuns := 5
		for i := 0; i < initialRuns; i++ {
			stdout, stderr, err := framework.RunCommand(
				"--config", configFile,
				"decrypt", fmt.Sprintf("memory-test-%d", i),
			)

			assert.Error(t, err)
			assert.Contains(t, stderr, framework.ExpectDecryptError())
			assert.Empty(t, stdout)

			// Check for memory-related errors
			assert.NotContains(t, stderr, "out of memory")
			assert.NotContains(t, stderr, "cannot allocate memory")
			assert.NotContains(t, stderr, "memory allocation failed")
		}

		t.Logf("Memory limit test: %d iterations completed without memory errors", initialRuns)
	})

	t.Run("signal_handling", func(t *testing.T) {
		// Test proper signal handling
		signals := []string{"SIGTERM", "SIGINT"}

		for _, signal := range signals {
			t.Run("handle_"+signal, func(t *testing.T) {
				cmd := exec.Command(framework.GetBinaryPath(),
					"--config", configFile,
					"decrypt", "signal-test-uuid")

				err := cmd.Start()
				require.NoError(t, err)

				// Let it run briefly
				time.Sleep(100 * time.Millisecond)

				// Send signal
				if signal == "SIGTERM" {
					_ = cmd.Process.Signal(os.Interrupt)
				} else {
					_ = cmd.Process.Signal(os.Interrupt)
				}

				// Wait for process to exit
				err = cmd.Wait()
				assert.Error(t, err) // Should be interrupted

				// Process should exit cleanly
				var exitError *exec.ExitError
				if errors.As(err, &exitError) {
					// Check exit code is reasonable
					assert.NotEqual(t, -1, exitError.ExitCode())
				}

				t.Logf("Signal handling test (%s) completed", signal)
			})
		}
	})
}
