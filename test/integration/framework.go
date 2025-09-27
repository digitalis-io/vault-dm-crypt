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

	"github.com/sirupsen/logrus"
)

// TestFramework provides integration testing infrastructure
type TestFramework struct {
	t           *testing.T
	logger      *logrus.Logger
	vaultAddr   string
	vaultToken  string
	tempDir     string
	binaryPath  string
	loopDevices []string
}

// NewTestFramework creates a new test framework instance
func NewTestFramework(t *testing.T) *TestFramework {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	return &TestFramework{
		t:      t,
		logger: logger,
	}
}

// Setup initializes the test environment
func (tf *TestFramework) Setup() error {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "vault-dm-crypt-test-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	tf.tempDir = tempDir

	// Build or locate the binary
	if err := tf.buildBinary(); err != nil {
		return fmt.Errorf("failed to build binary: %w", err)
	}

	// Note: In a real test environment, you would start a Vault server here
	// For now, we're using a mock configuration
	tf.vaultAddr = "http://localhost:8200"
	tf.vaultToken = "test-root-token"

	return nil
}

// Cleanup tears down the test environment
func (tf *TestFramework) Cleanup() {
	// Clean up loop devices
	for _, device := range tf.loopDevices {
		cmd := exec.Command("losetup", "-d", device)
		_ = cmd.Run()
	}

	// Remove temporary directory
	if tf.tempDir != "" {
		_ = os.RemoveAll(tf.tempDir)
	}
}

// buildBinary compiles the vault-dm-crypt binary for testing
func (tf *TestFramework) buildBinary() error {
	projectRoot, err := tf.findProjectRoot()
	if err != nil {
		return err
	}

	// Use the pre-built binary from the build directory
	preBuildBinaryPath := filepath.Join(projectRoot, "build", "vault-dm-crypt")

	// Check if the pre-built binary exists
	if _, err := os.Stat(preBuildBinaryPath); err == nil {
		tf.binaryPath = preBuildBinaryPath
		tf.t.Logf("Using pre-built binary: %s", tf.binaryPath)
	} else {
		tf.t.Logf("Pre-built binary not found at %s, building new one: %v", preBuildBinaryPath, err)
		// Fall back to building the binary if it doesn't exist
		binaryPath := filepath.Join(tf.tempDir, "vault-dm-crypt")
		tf.binaryPath = binaryPath

		cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/vault-dm-crypt")
		cmd.Dir = projectRoot
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to build binary: %w", err)
		}
	}

	return nil
}

// findProjectRoot finds the project root directory
func (tf *TestFramework) findProjectRoot() (string, error) {
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

	return "", fmt.Errorf("could not find project root (go.mod)")
}

// RunCommand runs a vault-dm-crypt command with the given arguments
func (tf *TestFramework) RunCommand(args ...string) (stdout string, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, tf.binaryPath, args...)
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+tf.vaultAddr,
		"VAULT_TOKEN="+tf.vaultToken,
	)

	// Capture both stdout and stderr
	stdoutBytes, err := cmd.CombinedOutput()

	// For now, return combined output as stderr when there's an error
	if err != nil {
		return "", string(stdoutBytes), err
	}

	return string(stdoutBytes), "", nil
}

// CreateLoopDevice creates a loop device for testing
func (tf *TestFramework) CreateLoopDevice(sizeMB int) (string, error) {
	// Create a temporary file for the loop device
	tempFile := filepath.Join(tf.tempDir, fmt.Sprintf("loop-device-%d.img", len(tf.loopDevices)))

	// Create the file with specified size
	cmd := exec.Command("dd", "if=/dev/zero", fmt.Sprintf("of=%s", tempFile), "bs=1M", fmt.Sprintf("count=%d", sizeMB))
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to create loop device file: %w", err)
	}

	// Create loop device
	cmd = exec.Command("losetup", "-f", tempFile, "--show")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to create loop device: %w", err)
	}

	device := strings.TrimSpace(string(output))
	tf.loopDevices = append(tf.loopDevices, device)

	return device, nil
}

// CreateTestConfig creates a test configuration file
func (tf *TestFramework) CreateTestConfig(vaultAddr, roleID, secretID string) (string, error) {
	configContent := fmt.Sprintf(`[vault]
url = "%s"
backend = "secret"
approle = "%s"
secret_id = "%s"
timeout = 30
retry_max = 3
retry_delay = 5

[logging]
level = "debug"
format = "text"
output = "stdout"
`, vaultAddr, roleID, secretID)

	configFile := filepath.Join(tf.tempDir, "test-config.toml")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		return "", fmt.Errorf("failed to create config file: %w", err)
	}

	return configFile, nil
}

// GetVaultConfig returns the Vault configuration for testing
func (tf *TestFramework) GetVaultConfig() (vaultAddr, roleID, secretID string) {
	// Return mock values for testing
	// In a real test environment, these would come from the actual Vault server
	return tf.vaultAddr, "test-role-id", "test-secret-id"
}

// GetTempDir returns the temporary directory path
func (tf *TestFramework) GetTempDir() string {
	return tf.tempDir
}

// GetBinaryPath returns the path to the built binary
func (tf *TestFramework) GetBinaryPath() string {
	return tf.binaryPath
}

// RequireRoot skips the test if not running as root
func (tf *TestFramework) RequireRoot() {
	if os.Geteuid() != 0 {
		tf.t.Skip("This test requires root privileges")
	}
}

// RequireDocker skips the test if Docker is not available
func (tf *TestFramework) RequireDocker() {
	// For now, we're not using Docker, so this is a no-op
	// In a real implementation, you would check if Docker is available
}

// RequireCommands skips the test if required commands are not available
func (tf *TestFramework) RequireCommands(commands ...string) {
	for _, cmd := range commands {
		if _, err := exec.LookPath(cmd); err != nil {
			tf.t.Skipf("Required command '%s' is not available", cmd)
		}
	}
}

// IsRoot returns true if running with root privileges
func (tf *TestFramework) IsRoot() bool {
	return os.Geteuid() == 0
}

// ExpectDecryptError returns the expected error message for decrypt operations
// based on whether we're running as root or not
func (tf *TestFramework) ExpectDecryptError() string {
	if tf.IsRoot() {
		return "device with UUID"
	}
	return "root privileges"
}

// ExpectEncryptError returns the expected error message for encrypt operations
// based on whether we're running as root or not
func (tf *TestFramework) ExpectEncryptError() string {
	if tf.IsRoot() {
		return "device validation failed"
	}
	return "root privileges"
}
