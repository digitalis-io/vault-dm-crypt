//go:build integration
// +build integration

package integration

import (
	"testing"
)

// SetupTest is the main function tests should use to get a framework
// It automatically handles shared vs individual Vault instances
func SetupTest(t *testing.T) *TestFramework {
	var framework *TestFramework

	// If using shared Vault, get the shared instance
	if useSharedVault && sharedFramework != nil {
		// Create a wrapper that uses shared resources but has its own test context
		framework = &TestFramework{
			t:             t,
			logger:        sharedFramework.logger,
			vaultAddr:     sharedFramework.vaultAddr,
			vaultToken:    sharedFramework.vaultToken,
			tempDir:       sharedFramework.tempDir,
			binaryPath:    sharedFramework.binaryPath,
			dockerStarted: true, // Already started by TestMain
			projectRoot:   sharedFramework.projectRoot,
			roleID:        sharedFramework.roleID,
			secretID:      sharedFramework.secretID,
			loopDevices:   []string{}, // Each test manages its own loop devices
		}
		// No need to call Setup() or RequireDocker() - already done
		return framework
	}

	// Fall back to creating an individual framework
	framework = NewTestFramework(t)

	// Setup the individual framework
	if err := framework.Setup(); err != nil {
		t.Fatalf("Failed to setup test framework: %v", err)
	}

	// RequireDocker will start the containers
	framework.RequireDocker()

	// Register cleanup
	t.Cleanup(func() {
		framework.Cleanup()
	})

	return framework
}
