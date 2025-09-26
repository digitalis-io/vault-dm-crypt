package integration

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSuiteRunner runs comprehensive integration test suites based on environment
func TestSuiteRunner(t *testing.T) {
	// Check environment and capabilities
	env := detectTestEnvironment()

	t.Logf("Detected test environment: %+v", env)

	// Run appropriate test suites based on environment
	t.Run("basic_functionality", func(t *testing.T) {
		if !env.DockerAvailable {
			t.Skip("Docker not available - skipping basic functionality tests")
		}

		// Run basic tests that don't require root
		runBasicTestSuite(t)
	})

	t.Run("root_required_tests", func(t *testing.T) {
		if !env.IsRoot {
			t.Skip("Root privileges not available - skipping dm-crypt tests")
		}
		if !env.DockerAvailable {
			t.Skip("Docker not available - skipping root tests")
		}

		// Run tests that require root privileges
		runRootTestSuite(t)
	})

	t.Run("performance_tests", func(t *testing.T) {
		if !env.DockerAvailable {
			t.Skip("Docker not available - skipping performance tests")
		}
		if env.IsCI && !env.PerformanceTestsEnabled {
			t.Skip("Performance tests disabled in CI environment")
		}

		// Run performance and stress tests
		runPerformanceTestSuite(t)
	})

	t.Run("extended_tests", func(t *testing.T) {
		if !env.DockerAvailable {
			t.Skip("Docker not available - skipping extended tests")
		}
		if env.IsCI && !env.ExtendedTestsEnabled {
			t.Skip("Extended tests disabled in CI environment")
		}

		// Run extended test scenarios
		runExtendedTestSuite(t)
	})
}

// TestEnvironment describes the testing environment capabilities
type TestEnvironment struct {
	IsRoot                  bool
	DockerAvailable         bool
	SystemdAvailable        bool
	CryptsetupAvailable     bool
	IsCI                    bool
	PerformanceTestsEnabled bool
	ExtendedTestsEnabled    bool
	Platform                string
	GoVersion               string
}

// detectTestEnvironment analyzes the current environment
func detectTestEnvironment() TestEnvironment {
	env := TestEnvironment{
		IsRoot:                  os.Geteuid() == 0,
		IsCI:                    os.Getenv("CI") != "",
		PerformanceTestsEnabled: os.Getenv("RUN_PERFORMANCE_TESTS") == "true",
		ExtendedTestsEnabled:    os.Getenv("RUN_EXTENDED_TESTS") == "true",
		Platform:                runtime.GOOS,
		GoVersion:               runtime.Version(),
	}

	// Check for required commands
	env.DockerAvailable = commandAvailable("docker")
	env.SystemdAvailable = commandAvailable("systemctl")
	env.CryptsetupAvailable = commandAvailable("cryptsetup")

	return env
}

// commandAvailable checks if a command is available in PATH
func commandAvailable(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// runBasicTestSuite runs tests that don't require root privileges
func runBasicTestSuite(t *testing.T) {
	t.Log("Running basic functionality test suite...")

	// These tests should run in any environment with Docker
	testCategories := []struct {
		name     string
		testFunc func(*testing.T)
		required bool
	}{
		{"vault_integration", TestVaultIntegration, true},
		{"command_line_interface", TestCommandLineInterface, true},
		{"error_handling", TestErrorHandling, true},
		{"vault_comprehensive", TestVaultComprehensive, false},
		{"vault_failure_scenarios", TestVaultFailureScenarios, false},
		{"vault_security_features", TestVaultSecurityFeatures, false},
	}

	for _, tc := range testCategories {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			tc.testFunc(t)
			duration := time.Since(start)
			t.Logf("Test category '%s' completed in %v", tc.name, duration)
		})
	}
}

// runRootTestSuite runs tests that require root privileges
func runRootTestSuite(t *testing.T) {
	t.Log("Running root-required test suite...")

	testCategories := []struct {
		name     string
		testFunc func(*testing.T)
	}{
		{"end_to_end_encrypt_decrypt", TestEndToEndEncryptDecrypt},
		{"dmcrypt_operations", TestDMCryptOperations},
		{"vault_secret_lifecycle", TestVaultSecretLifecycle},
		{"system_integration", TestSystemIntegration},
		{"systemd_integration", TestSystemdIntegration},
	}

	for _, tc := range testCategories {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			tc.testFunc(t)
			duration := time.Since(start)
			t.Logf("Root test category '%s' completed in %v", tc.name, duration)
		})
	}
}

// runPerformanceTestSuite runs performance and stress tests
func runPerformanceTestSuite(t *testing.T) {
	t.Log("Running performance test suite...")

	testCategories := []struct {
		name     string
		testFunc func(*testing.T)
	}{
		{"performance_characteristics", TestPerformanceCharacteristics},
		{"stress_scenarios", TestStressScenarios},
		{"advanced_scenarios", TestAdvancedScenarios},
	}

	for _, tc := range testCategories {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			tc.testFunc(t)
			duration := time.Since(start)
			t.Logf("Performance test category '%s' completed in %v", tc.name, duration)
		})
	}
}

// runExtendedTestSuite runs extended test scenarios
func runExtendedTestSuite(t *testing.T) {
	t.Log("Running extended test suite...")

	testCategories := []struct {
		name     string
		testFunc func(*testing.T)
	}{
		{"error_recovery_scenarios", TestErrorRecoveryScenarios},
		{"edge_case_handling", TestEdgeCaseHandling},
		{"failure_recovery", TestFailureRecovery},
		{"systemd_environment", TestSystemdEnvironment},
	}

	for _, tc := range testCategories {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			tc.testFunc(t)
			duration := time.Since(start)
			t.Logf("Extended test category '%s' completed in %v", tc.name, duration)
		})
	}
}

// TestQuickSuite runs a minimal test suite for quick validation
func TestQuickSuite(t *testing.T) {
	if os.Getenv("QUICK_TESTS") != "true" {
		t.Skip("Quick test suite not enabled (set QUICK_TESTS=true)")
	}

	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	t.Log("Running quick validation suite...")

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	// Quick smoke tests
	t.Run("version_check", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand("--version")
		require.NoError(t, err)
		require.Contains(t, stdout, "vault-dm-crypt")
		require.Empty(t, stderr)
	})

	t.Run("help_check", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand("--help")
		require.NoError(t, err)
		require.Contains(t, stdout, "encrypt")
		require.Contains(t, stdout, "decrypt")
		require.Empty(t, stderr)
	})

	t.Run("config_validation", func(t *testing.T) {
		stdout, stderr, err := framework.RunCommand("--config", configFile, "decrypt", "quick-test-uuid")
		require.Error(t, err)
		require.Contains(t, stderr, "device with UUID")
		require.Empty(t, stdout)
	})

	t.Log("Quick validation suite completed successfully")
}

// TestCompatibilityMatrix runs tests across different configurations
func TestCompatibilityMatrix(t *testing.T) {
	if os.Getenv("RUN_COMPATIBILITY_TESTS") != "true" {
		t.Skip("Compatibility matrix tests not enabled (set RUN_COMPATIBILITY_TESTS=true)")
	}

	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()

	// Test different configuration variations
	configVariations := []struct {
		name   string
		config string
	}{
		{
			name: "minimal_config",
			config: fmt.Sprintf(`[vault]
url = "%s"
backend = "secret"
approle = "%s"
secret_id = "%s"
`, vaultAddr, roleID, secretID),
		},
		{
			name: "full_config",
			config: fmt.Sprintf(`[vault]
url = "%s"
backend = "secret"
approle = "%s"
secret_id = "%s"
timeout = 30
retry_max = 3
retry_delay = 5

[logging]
level = "info"
format = "text"
output = "stdout"
`, vaultAddr, roleID, secretID),
		},
		{
			name: "debug_config",
			config: fmt.Sprintf(`[vault]
url = "%s"
backend = "secret"
approle = "%s"
secret_id = "%s"
timeout = 60
retry_max = 5
retry_delay = 2

[logging]
level = "debug"
format = "json"
output = "stdout"
`, vaultAddr, roleID, secretID),
		},
	}

	for _, variation := range configVariations {
		t.Run(variation.name, func(t *testing.T) {
			configFile := framework.GetTempDir() + "/" + variation.name + "-config.toml"
			err := os.WriteFile(configFile, []byte(variation.config), 0644)
			require.NoError(t, err)

			// Test basic functionality with this configuration
			stdout, stderr, err := framework.RunCommand("--config", configFile, "decrypt", "compat-test-uuid")
			require.Error(t, err)
			require.Contains(t, stderr, "device with UUID")
			require.Empty(t, stdout)

			t.Logf("Configuration variation '%s' validated successfully", variation.name)
		})
	}
}

// TestBenchmarkSuite runs benchmark-style tests for performance measurement
func TestBenchmarkSuite(t *testing.T) {
	if os.Getenv("RUN_BENCHMARKS") != "true" {
		t.Skip("Benchmark tests not enabled (set RUN_BENCHMARKS=true)")
	}

	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	benchmarks := []struct {
		name       string
		iterations int
		operation  func() error
	}{
		{
			name:       "version_command",
			iterations: 100,
			operation: func() error {
				_, _, err := framework.RunCommand("--version")
				return err
			},
		},
		{
			name:       "help_command",
			iterations: 50,
			operation: func() error {
				_, _, err := framework.RunCommand("--help")
				return err
			},
		},
		{
			name:       "decrypt_nonexistent",
			iterations: 20,
			operation: func() error {
				_, _, _ = framework.RunCommand("--config", configFile, "decrypt", "benchmark-uuid")
				// Error is expected
				return nil
			},
		},
	}

	for _, benchmark := range benchmarks {
		t.Run(benchmark.name, func(t *testing.T) {
			var totalDuration time.Duration
			successCount := 0

			for i := 0; i < benchmark.iterations; i++ {
				start := time.Now()
				err := benchmark.operation()
				duration := time.Since(start)

				totalDuration += duration
				if err == nil {
					successCount++
				}
			}

			avgDuration := totalDuration / time.Duration(benchmark.iterations)
			successRate := float64(successCount) / float64(benchmark.iterations)

			t.Logf("Benchmark '%s' results:", benchmark.name)
			t.Logf("  Iterations: %d", benchmark.iterations)
			t.Logf("  Average duration: %v", avgDuration)
			t.Logf("  Total duration: %v", totalDuration)
			t.Logf("  Success rate: %.1f%%", successRate*100)
			t.Logf("  Operations per second: %.2f", float64(benchmark.iterations)/totalDuration.Seconds())
		})
	}
}
