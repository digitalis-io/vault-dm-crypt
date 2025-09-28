//go:build integration
// +build integration

package integration

import (
	"flag"
	"fmt"
	"log"
	"os"
	"testing"
)

// TestMain runs once for the entire test suite
func TestMain(m *testing.M) {
	// Parse test flags
	flag.BoolVar(&useSharedVault, "shared-vault", true, "Use a shared Vault instance for all tests")
	flag.Parse()

	var exitCode int

	if useSharedVault {
		log.Println("Running integration tests with SHARED Vault instance")
		exitCode = runWithSharedVault(m)
	} else {
		log.Println("Running integration tests with INDIVIDUAL Vault instances per test")
		exitCode = runWithIndividualVault(m)
	}

	os.Exit(exitCode)
}

// runWithSharedVault starts Vault once and shares it across all tests
func runWithSharedVault(m *testing.M) int {
	// Create a dummy test.T for framework initialization
	// This is safe as we only use it for logging during setup
	dummyT := &testing.T{}

	sharedFramework = NewTestFramework(dummyT)

	// Check if Docker is available
	if err := checkDocker(); err != nil {
		log.Printf("Docker not available, skipping integration tests: %v", err)
		return 0
	}

	// Setup the shared framework (builds binary, creates temp dir)
	if err := sharedFramework.Setup(); err != nil {
		log.Fatalf("Failed to setup shared test framework: %v", err)
	}

	// Start Docker/Vault once
	if err := sharedFramework.startDocker(); err != nil {
		log.Fatalf("Failed to start Docker/Vault: %v", err)
	}
	sharedFramework.dockerStarted = true

	// Run all tests
	exitCode := m.Run()

	// Cleanup after all tests
	log.Println("Cleaning up shared test resources...")
	sharedFramework.Cleanup()

	return exitCode
}

// runWithIndividualVault lets each test manage its own Vault instance
func runWithIndividualVault(m *testing.M) int {
	// Just run the tests - each will create its own framework
	return m.Run()
}

// checkDocker verifies Docker is available
func checkDocker() error {
	if _, err := os.Stat("/var/run/docker.sock"); os.IsNotExist(err) {
		return fmt.Errorf("Docker socket not found")
	}
	return nil
}

// GetSharedFramework returns the shared framework instance if available
func GetSharedFramework(t *testing.T) *TestFramework {
	if useSharedVault && sharedFramework != nil {
		// Create a wrapper that uses the shared framework but with the test's t
		wrapper := &TestFramework{
			t:             t,
			logger:        sharedFramework.logger,
			vaultAddr:     sharedFramework.vaultAddr,
			vaultToken:    sharedFramework.vaultToken,
			tempDir:       sharedFramework.tempDir,
			binaryPath:    sharedFramework.binaryPath,
			dockerStarted: sharedFramework.dockerStarted,
			projectRoot:   sharedFramework.projectRoot,
			roleID:        sharedFramework.roleID,
			secretID:      sharedFramework.secretID,
			loopDevices:   []string{}, // Each test manages its own loop devices
		}
		return wrapper
	}

	// Fall back to creating a new framework
	framework := NewTestFramework(t)
	return framework
}
