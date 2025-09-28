//go:build integration
// +build integration

package integration

import (
	"context"
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
}
