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
	t             *testing.T
	logger        *logrus.Logger
	vaultAddr     string
	vaultToken    string
	tempDir       string
	binaryPath    string
	loopDevices   []string
	dockerStarted bool
	projectRoot   string
	roleID        string
	secretID      string
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
	// Find project root early
	projectRoot, err := tf.findProjectRoot()
	if err != nil {
		return fmt.Errorf("failed to find project root: %w", err)
	}
	tf.projectRoot = projectRoot

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

	// Set Vault configuration
	tf.vaultAddr = "http://localhost:8200"
	tf.vaultToken = "test-root-token"

	return nil
}

// Cleanup tears down the test environment
func (tf *TestFramework) Cleanup() {
	// Only stop Docker if this framework instance started it
	// (not if we're using a shared instance)
	if tf.dockerStarted && !isUsingSharedVault() {
		tf.stopDocker()
	}

	// Clean up loop devices
	for _, device := range tf.loopDevices {
		cmd := exec.Command("losetup", "-d", device)
		_ = cmd.Run()
	}

	// Don't remove temp directory if using shared framework
	if tf.tempDir != "" && !isUsingSharedVault() {
		_ = os.RemoveAll(tf.tempDir)
	}
}

// isUsingSharedVault checks if we're using the shared Vault instance
func isUsingSharedVault() bool {
	return useSharedVault && sharedFramework != nil
}

// buildBinary compiles the vault-dm-crypt binary for testing
func (tf *TestFramework) buildBinary() error {
	projectRoot := tf.projectRoot

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
	)

	// Capture both stdout and stderr
	stdoutBytes, err := cmd.CombinedOutput()

	// For now, return combined output as stderr when there's an error
	if err != nil {
		return "", string(stdoutBytes), err
	}

	return string(stdoutBytes), "", nil
}

// RunVaultCommand runs a vault CLI command with the given arguments (includes VAULT_TOKEN)
func (tf *TestFramework) RunVaultCommand(args ...string) (stdout string, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "vault", args...)
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
	// Return the actual values from the configured Vault instance
	return tf.vaultAddr, tf.roleID, tf.secretID
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

// RequireDocker skips the test if Docker is not available, otherwise starts Vault container
func (tf *TestFramework) RequireDocker() {
	// Check if Docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		tf.t.Skip("Docker is not available")
	}

	// Check if docker-compose (v1) or docker compose (v2) is available
	hasDockerCompose := false
	if _, err := exec.LookPath("docker-compose"); err == nil {
		hasDockerCompose = true
	} else {
		// Try docker compose (v2)
		cmd := exec.Command("docker", "compose", "version")
		if err := cmd.Run(); err == nil {
			hasDockerCompose = true
		}
	}

	if !hasDockerCompose {
		tf.t.Skip("Docker Compose is not available")
	}

	// Initialize Vault configuration if not already set
	if tf.vaultAddr == "" {
		tf.vaultAddr = "http://localhost:8200"
		tf.vaultToken = "test-root-token"
	}

	// If using shared Vault, don't start Docker again
	if isUsingSharedVault() {
		// Vault should already be running from TestMain
		return
	}

	// Start Docker containers if not already started
	if !tf.dockerStarted {
		if err := tf.startDocker(); err != nil {
			tf.t.Fatalf("Failed to start Docker containers: %v", err)
		}
		tf.dockerStarted = true
	}
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

// startDocker starts the Docker containers using docker-compose
func (tf *TestFramework) startDocker() error {
	// Find the directory containing docker-compose.yml
	composeDir, err := tf.findComposeDir()
	if err != nil {
		return fmt.Errorf("failed to find docker-compose.yml: %w", err)
	}

	// Stop any existing containers first
	tf.logger.Debug("Stopping any existing Docker containers...")
	cmd := tf.createComposeCommand("down", "--remove-orphans")
	cmd.Dir = composeDir
	_ = cmd.Run() // Ignore errors, containers might not exist

	// Start the containers
	tf.logger.Debug("Starting Docker containers...")
	cmd = tf.createComposeCommand("up", "-d")
	cmd.Dir = composeDir
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start docker-compose: %w", err)
	}

	// Wait for Vault to be ready
	tf.logger.Debug("Waiting for Vault to be ready...")
	if err := tf.waitForVault(); err != nil {
		return err
	}

	// Set up Vault for testing (AppRole, policies, etc.)
	tf.logger.Debug("Setting up Vault for testing...")
	return tf.setupVaultForTesting()
}

// stopDocker stops the Docker containers
func (tf *TestFramework) stopDocker() {
	// Find the directory containing docker-compose.yml
	composeDir, err := tf.findComposeDir()
	if err != nil {
		tf.logger.Warnf("Failed to find docker-compose.yml: %v", err)
		return
	}

	tf.logger.Debug("Stopping Docker containers...")
	cmd := tf.createComposeCommand("down", "--remove-orphans")
	cmd.Dir = composeDir
	if err := cmd.Run(); err != nil {
		tf.logger.Warnf("Failed to stop docker-compose: %v", err)
	}
}

// createComposeCommand creates the appropriate docker-compose command (v1 or v2)
func (tf *TestFramework) createComposeCommand(args ...string) *exec.Cmd {
	// Try docker-compose first (v1)
	if _, err := exec.LookPath("docker-compose"); err == nil {
		return exec.Command("docker-compose", args...)
	}

	// Use docker compose (v2)
	cmdArgs := append([]string{"compose"}, args...)
	return exec.Command("docker", cmdArgs...)
}

// waitForVault waits for Vault to become available
func (tf *TestFramework) waitForVault() error {
	maxRetries := 30
	retryDelay := 2 * time.Second

	for i := 0; i < maxRetries; i++ {
		// Try to connect to Vault health endpoint
		url := tf.vaultAddr + "/v1/sys/health"
		cmd := exec.Command("curl", "-s", "-f", url)
		if err := cmd.Run(); err == nil {
			tf.logger.Debug("Vault is ready!")
			return nil
		}

		tf.logger.Debugf("Vault not ready yet, retry %d/%d...", i+1, maxRetries)
		time.Sleep(retryDelay)
	}

	return fmt.Errorf("vault did not become ready within %v", time.Duration(maxRetries)*retryDelay)
}

// findComposeDir finds the directory containing docker-compose.yml
func (tf *TestFramework) findComposeDir() (string, error) {
	// Check current directory first
	currentDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(filepath.Join(currentDir, "docker-compose.yml")); err == nil {
		return currentDir, nil
	}

	// Check test/integration relative to project root
	integrationDir := filepath.Join(tf.projectRoot, "test", "integration")
	if _, err := os.Stat(filepath.Join(integrationDir, "docker-compose.yml")); err == nil {
		return integrationDir, nil
	}

	return "", fmt.Errorf("docker-compose.yml not found")
}

// setupVaultForTesting configures Vault for integration testing
func (tf *TestFramework) setupVaultForTesting() error {
	// Enable AppRole auth method
	if err := tf.runVaultCommand("auth", "enable", "approle"); err != nil {
		// AppRole might already be enabled, check the error
		if !strings.Contains(err.Error(), "path is already in use") {
			return fmt.Errorf("failed to enable AppRole auth: %w", err)
		}
	}

	// Create a policy for the test role
	policyName := "vault-dm-crypt-test-policy"
	policyRules := `path "secret/data/vaultlocker/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/vaultlocker/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/vaultlocker/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}`

	// Write policy to a temporary file
	policyFile := filepath.Join(tf.tempDir, "test-policy.hcl")
	if err := os.WriteFile(policyFile, []byte(policyRules), 0644); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	if err := tf.runVaultCommand("policy", "write", policyName, policyFile); err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	// Create AppRole
	roleName := "vault-dm-crypt-test-role"
	if err := tf.runVaultCommand("write", "auth/approle/role/"+roleName,
		"token_policies="+policyName,
		"token_ttl=1h",
		"token_max_ttl=4h"); err != nil {
		return fmt.Errorf("failed to create AppRole: %w", err)
	}

	// Get role_id
	roleIDOutput, err := tf.runVaultCommandWithOutput("read", "-field=role_id", "auth/approle/role/"+roleName+"/role-id")
	if err != nil {
		return fmt.Errorf("failed to get role_id: %w", err)
	}
	tf.roleID = strings.TrimSpace(roleIDOutput)
	tf.logger.Debugf("AppRole role_id: %s", tf.roleID)

	// Generate secret_id
	secretIDOutput, err := tf.runVaultCommandWithOutput("write", "-field=secret_id", "-force", "auth/approle/role/"+roleName+"/secret-id")
	if err != nil {
		return fmt.Errorf("failed to generate secret_id: %w", err)
	}
	tf.secretID = strings.TrimSpace(secretIDOutput)
	tf.logger.Debugf("AppRole secret_id: %s", tf.secretID)

	tf.logger.Debug("Vault setup completed successfully")
	return nil
}

// runVaultCommand runs a vault command with the configured token
func (tf *TestFramework) runVaultCommand(args ...string) error {
	cmd := exec.Command("vault", args...)
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+tf.vaultAddr,
		"VAULT_TOKEN="+tf.vaultToken,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("vault command failed: %w, output: %s", err, string(output))
	}
	return nil
}

// runVaultCommandWithOutput runs a vault command and returns the output
func (tf *TestFramework) runVaultCommandWithOutput(args ...string) (string, error) {
	cmd := exec.Command("vault", args...)
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+tf.vaultAddr,
		"VAULT_TOKEN="+tf.vaultToken,
	)
	output, err := cmd.Output()
	return string(output), err
}

// runVaultCommandWithStdin runs a vault command with stdin input
func (tf *TestFramework) runVaultCommandWithStdin(args []string, stdinData string) error {
	// Extract the last argument if it's "-" (stdin indicator)
	var cmdArgs []string
	var useStdin bool
	for _, arg := range args {
		if arg == "-" {
			useStdin = true
		} else {
			cmdArgs = append(cmdArgs, arg)
		}
	}

	cmd := exec.Command("vault", cmdArgs...)
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+tf.vaultAddr,
		"VAULT_TOKEN="+tf.vaultToken,
	)

	if useStdin {
		cmd.Stdin = strings.NewReader(stdinData)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("vault command failed: %w, output: %s", err, string(output))
	}
	return nil
}
