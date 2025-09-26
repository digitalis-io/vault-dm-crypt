package integration

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/sirupsen/logrus"
)

// TestFramework provides integration testing infrastructure
type TestFramework struct {
	t              *testing.T
	logger         *logrus.Logger
	dockerClient   *client.Client
	vaultContainer string
	vaultAddr      string
	vaultToken     string
	tempDir        string
	binaryPath     string
	loopDevices    []string
}

// NewTestFramework creates a new integration test framework
func NewTestFramework(t *testing.T) *TestFramework {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.SetOutput(io.Discard) // Suppress logs during tests unless needed

	return &TestFramework{
		t:           t,
		logger:      logger,
		loopDevices: make([]string, 0),
	}
}

// Setup initializes the test environment
func (tf *TestFramework) Setup() error {
	tf.t.Helper()

	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "vault-dm-crypt-test-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	tf.tempDir = tempDir

	// Build the binary for testing
	if err := tf.buildBinary(); err != nil {
		return fmt.Errorf("failed to build binary: %w", err)
	}

	// Initialize Docker client
	if err := tf.initDocker(); err != nil {
		return fmt.Errorf("failed to initialize Docker: %w", err)
	}

	// Start Vault container
	if err := tf.startVaultContainer(); err != nil {
		return fmt.Errorf("failed to start Vault container: %w", err)
	}

	// Configure Vault for testing
	if err := tf.configureVault(); err != nil {
		return fmt.Errorf("failed to configure Vault: %w", err)
	}

	return nil
}

// Cleanup tears down the test environment
func (tf *TestFramework) Cleanup() {
	tf.t.Helper()

	// Cleanup loop devices
	for _, device := range tf.loopDevices {
		tf.cleanupLoopDevice(device)
	}

	// Stop and remove Vault container
	if tf.vaultContainer != "" && tf.dockerClient != nil {
		ctx := context.Background()
		tf.dockerClient.ContainerStop(ctx, tf.vaultContainer, container.StopOptions{})
		tf.dockerClient.ContainerRemove(ctx, tf.vaultContainer, types.ContainerRemoveOptions{Force: true})
	}

	// Cleanup temporary directory
	if tf.tempDir != "" {
		os.RemoveAll(tf.tempDir)
	}

	// Close Docker client
	if tf.dockerClient != nil {
		tf.dockerClient.Close()
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

// initDocker initializes the Docker client
func (tf *TestFramework) initDocker() error {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	tf.dockerClient = dockerClient

	// Test Docker connectivity
	ctx := context.Background()
	_, err = dockerClient.Ping(ctx)
	if err != nil {
		return fmt.Errorf("Docker is not available: %w", err)
	}

	return nil
}

// startVaultContainer starts a Vault container for testing
func (tf *TestFramework) startVaultContainer() error {
	ctx := context.Background()

	// Pull Vault image if not present
	_, _, err := tf.dockerClient.ImageInspectWithRaw(ctx, "vault:latest")
	if err != nil {
		tf.logger.Debug("Pulling Vault Docker image...")
		reader, err := tf.dockerClient.ImagePull(ctx, "vault:latest", types.ImagePullOptions{})
		if err != nil {
			return fmt.Errorf("failed to pull Vault image: %w", err)
		}
		defer reader.Close()
		// Wait for image pull to complete
		io.Copy(io.Discard, reader)
	}

	// Create container
	config := &container.Config{
		Image: "vault:latest",
		Env: []string{
			"VAULT_DEV_ROOT_TOKEN_ID=test-root-token",
			"VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		},
		ExposedPorts: nat.PortSet{
			"8200/tcp": struct{}{},
		},
		Cmd: []string{"vault", "server", "-dev"},
	}

	hostConfig := &container.HostConfig{
		PortBindings: nat.PortMap{
			"8200/tcp": []nat.PortBinding{{HostIP: "127.0.0.1", HostPort: "0"}}, // Random port
		},
		AutoRemove: true,
	}

	resp, err := tf.dockerClient.ContainerCreate(ctx, config, hostConfig, nil, nil, "")
	if err != nil {
		return fmt.Errorf("failed to create Vault container: %w", err)
	}

	tf.vaultContainer = resp.ID

	// Start container
	if err := tf.dockerClient.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("failed to start Vault container: %w", err)
	}

	// Get the assigned port
	containerInfo, err := tf.dockerClient.ContainerInspect(ctx, resp.ID)
	if err != nil {
		return fmt.Errorf("failed to inspect Vault container: %w", err)
	}

	port := containerInfo.NetworkSettings.Ports["8200/tcp"][0].HostPort
	tf.vaultAddr = fmt.Sprintf("http://127.0.0.1:%s", port)
	tf.vaultToken = "test-root-token"

	// Wait for Vault to be ready
	if err := tf.waitForVault(); err != nil {
		return fmt.Errorf("Vault failed to start: %w", err)
	}

	tf.logger.WithFields(logrus.Fields{
		"vault_addr":  tf.vaultAddr,
		"vault_token": tf.vaultToken,
	}).Debug("Vault container started successfully")

	return nil
}

// waitForVault waits for Vault to be ready
func (tf *TestFramework) waitForVault() error {
	timeout := time.Now().Add(30 * time.Second)
	for time.Now().Before(timeout) {
		cmd := exec.Command("curl", "-s", "-f", tf.vaultAddr+"/v1/sys/health")
		if err := cmd.Run(); err == nil {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("Vault failed to become ready within timeout")
}

// configureVault sets up Vault for testing
func (tf *TestFramework) configureVault() error {
	// Enable AppRole auth
	cmd := exec.Command("vault", "auth", "enable", "approle")
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+tf.vaultAddr,
		"VAULT_TOKEN="+tf.vaultToken,
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable AppRole auth: %w", err)
	}

	// Create a policy for the test role
	policyContent := `
path "secret/data/vaultlocker/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/vaultlocker/*" {
  capabilities = ["read", "list", "delete"]
}
`
	policyFile := filepath.Join(tf.tempDir, "test-policy.hcl")
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	cmd = exec.Command("vault", "policy", "write", "vault-dm-crypt-test", policyFile)
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+tf.vaultAddr,
		"VAULT_TOKEN="+tf.vaultToken,
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	// Create AppRole
	cmd = exec.Command("vault", "write", "auth/approle/role/test-role",
		"token_policies=vault-dm-crypt-test",
		"token_ttl=1h",
		"token_max_ttl=4h")
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+tf.vaultAddr,
		"VAULT_TOKEN="+tf.vaultToken,
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create AppRole: %w", err)
	}

	tf.logger.Debug("Vault configured successfully for testing")
	return nil
}

// GetVaultConfig returns Vault configuration for tests
func (tf *TestFramework) GetVaultConfig() (string, string, string) {
	// Get Role ID
	cmd := exec.Command("vault", "read", "-field=role_id", "auth/approle/role/test-role/role-id")
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+tf.vaultAddr,
		"VAULT_TOKEN="+tf.vaultToken,
	)
	roleIDBytes, err := cmd.Output()
	if err != nil {
		tf.t.Fatalf("Failed to get role ID: %v", err)
	}
	roleID := strings.TrimSpace(string(roleIDBytes))

	// Get Secret ID
	cmd = exec.Command("vault", "write", "-field=secret_id", "auth/approle/role/test-role/secret-id")
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+tf.vaultAddr,
		"VAULT_TOKEN="+tf.vaultToken,
	)
	secretIDBytes, err := cmd.Output()
	if err != nil {
		tf.t.Fatalf("Failed to get secret ID: %v", err)
	}
	secretID := strings.TrimSpace(string(secretIDBytes))

	return tf.vaultAddr, roleID, secretID
}

// CreateLoopDevice creates a loop device for testing dm-crypt operations
func (tf *TestFramework) CreateLoopDevice(sizeMB int) (string, error) {
	// Create a file to use as backing store
	imageFile := filepath.Join(tf.tempDir, fmt.Sprintf("test-device-%d.img", len(tf.loopDevices)))

	cmd := exec.Command("dd", "if=/dev/zero", "of="+imageFile, "bs=1M", fmt.Sprintf("count=%d", sizeMB))
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to create image file: %w", err)
	}

	// Create loop device
	cmd = exec.Command("losetup", "--find", "--show", imageFile)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to create loop device: %w", err)
	}

	loopDevice := strings.TrimSpace(string(output))
	tf.loopDevices = append(tf.loopDevices, loopDevice)

	tf.logger.WithFields(logrus.Fields{
		"image_file":  imageFile,
		"loop_device": loopDevice,
		"size_mb":     sizeMB,
	}).Debug("Created loop device")

	return loopDevice, nil
}

// cleanupLoopDevice removes a loop device
func (tf *TestFramework) cleanupLoopDevice(device string) {
	cmd := exec.Command("losetup", "-d", device)
	cmd.Run() // Ignore errors during cleanup
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

	configFile := filepath.Join(tf.tempDir, "config.toml")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		return "", fmt.Errorf("failed to write config file: %w", err)
	}

	return configFile, nil
}

// RunCommand executes the vault-dm-crypt binary with given arguments
func (tf *TestFramework) RunCommand(args ...string) (string, string, error) {
	cmd := exec.Command(tf.binaryPath, args...)

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// GetTempDir returns the temporary directory for the test
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
	if _, err := exec.LookPath("docker"); err != nil {
		tf.t.Skip("Docker is not available")
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
