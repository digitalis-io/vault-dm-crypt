//go:build integration
// +build integration

package integration

import (
	"testing"
	"time"
)

// TestSharedVaultPerformance demonstrates the performance difference
func TestSharedVaultPerformance(t *testing.T) {
	if !useSharedVault {
		t.Skip("This test demonstrates shared Vault performance - run with default settings")
	}

	start := time.Now()

	// Get the shared framework (should be instant)
	framework := GetSharedFramework(t)
	framework.RequireDocker()

	setupTime := time.Since(start)

	t.Logf("Shared Vault setup time: %v (should be near-instant)", setupTime)

	// Verify it's actually working
	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	if vaultAddr == "" || roleID == "" || secretID == "" {
		t.Fatal("Vault configuration not available")
	}

	t.Logf("Successfully using shared Vault at %s", vaultAddr)
}

// TestIndividualVaultTiming shows the time for individual setup
func TestIndividualVaultTiming(t *testing.T) {
	if useSharedVault {
		t.Skip("This test measures individual Vault setup - run with -shared-vault=false")
	}

	start := time.Now()

	framework := NewTestFramework(t)
	if err := framework.Setup(); err != nil {
		t.Fatalf("Failed to setup: %v", err)
	}
	defer framework.Cleanup()

	framework.RequireDocker()

	setupTime := time.Since(start)

	t.Logf("Individual Vault setup time: %v", setupTime)

	// Verify it's working
	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	if vaultAddr == "" || roleID == "" || secretID == "" {
		t.Fatal("Vault configuration not available")
	}

	t.Logf("Successfully started individual Vault at %s", vaultAddr)
}
