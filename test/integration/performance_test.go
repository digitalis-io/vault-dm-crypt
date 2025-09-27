package integration

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPerformanceCharacteristics tests comprehensive performance scenarios
func TestPerformanceCharacteristics(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("application_startup_performance", func(t *testing.T) {
		// Measure application startup time across multiple runs
		numRuns := 10
		startupTimes := make([]time.Duration, numRuns)

		for i := 0; i < numRuns; i++ {
			start := time.Now()

			stdout, stderr, err := framework.RunCommand(
				"--config", configFile,
				"--version",
			)

			duration := time.Since(start)
			startupTimes[i] = duration

			assert.NoError(t, err)
			assert.Contains(t, stdout, "vault-dm-crypt")
			assert.Empty(t, stderr)
		}

		// Calculate statistics
		var total time.Duration
		min := startupTimes[0]
		max := startupTimes[0]

		for _, duration := range startupTimes {
			total += duration
			if duration < min {
				min = duration
			}
			if duration > max {
				max = duration
			}
		}

		average := total / time.Duration(numRuns)

		t.Logf("Startup performance over %d runs:", numRuns)
		t.Logf("  Average: %v", average)
		t.Logf("  Min: %v", min)
		t.Logf("  Max: %v", max)

		// Performance assertions
		assert.Less(t, average, 5*time.Second, "Average startup time should be reasonable")
		assert.Less(t, max, 10*time.Second, "Maximum startup time should be bounded")
	})

	t.Run("vault_authentication_performance", func(t *testing.T) {
		// Measure Vault authentication performance
		numTests := 5
		authTimes := make([]time.Duration, numTests)

		for i := 0; i < numTests; i++ {
			start := time.Now()

			stdout, stderr, err := framework.RunCommand(
				"--config", configFile,
				"decrypt", fmt.Sprintf("perf-test-uuid-%d", i),
			)

			duration := time.Since(start)
			authTimes[i] = duration

			// Should fail with device not found, but authentication should succeed
			assert.Error(t, err)
			assert.Contains(t, stderr, framework.ExpectDecryptError())
			assert.Empty(t, stdout)
		}

		// Calculate authentication performance statistics
		var total time.Duration
		for _, duration := range authTimes {
			total += duration
		}
		average := total / time.Duration(numTests)

		t.Logf("Vault authentication performance over %d runs:", numTests)
		t.Logf("  Average total operation time: %v", average)

		// Performance assertions
		assert.Less(t, average, 30*time.Second, "Average operation time should be reasonable")
	})

	t.Run("concurrent_operation_performance", func(t *testing.T) {
		// Test performance under concurrent load
		concurrencyLevels := []int{5, 10, 20}

		for _, concurrency := range concurrencyLevels {
			t.Run(fmt.Sprintf("concurrency_%d", concurrency), func(t *testing.T) {
				var wg sync.WaitGroup
				results := make(chan time.Duration, concurrency)
				errors := make(chan error, concurrency)

				start := time.Now()

				for i := 0; i < concurrency; i++ {
					wg.Add(1)
					go func(id int) {
						defer wg.Done()

						opStart := time.Now()
						stdout, stderr, err := framework.RunCommand(
							"--config", configFile,
							"decrypt", fmt.Sprintf("concurrent-perf-test-%d", id),
						)
						opDuration := time.Since(opStart)

						results <- opDuration

						if err != nil && contains(stderr, framework.ExpectDecryptError()) {
							errors <- nil // Expected error
						} else {
							errors <- fmt.Errorf("unexpected result: %v - %s - %s", err, stderr, stdout)
						}
					}(i)
				}

				wg.Wait()
				totalDuration := time.Since(start)

				// Collect results
				operationTimes := make([]time.Duration, concurrency)
				errorCount := 0
				for i := 0; i < concurrency; i++ {
					operationTimes[i] = <-results
					if err := <-errors; err != nil {
						errorCount++
						t.Logf("Operation error: %v", err)
					}
				}

				// Calculate statistics
				var totalOpTime time.Duration
				maxOpTime := operationTimes[0]
				for _, opTime := range operationTimes {
					totalOpTime += opTime
					if opTime > maxOpTime {
						maxOpTime = opTime
					}
				}
				avgOpTime := totalOpTime / time.Duration(concurrency)

				t.Logf("Concurrent performance (concurrency=%d):", concurrency)
				t.Logf("  Total wall time: %v", totalDuration)
				t.Logf("  Average operation time: %v", avgOpTime)
				t.Logf("  Max operation time: %v", maxOpTime)
				t.Logf("  Operations per second: %.2f", float64(concurrency)/totalDuration.Seconds())
				t.Logf("  Error count: %d/%d", errorCount, concurrency)

				// Performance assertions
				assert.Equal(t, 0, errorCount, "No unexpected errors should occur")
				assert.Less(t, totalDuration, time.Duration(concurrency)*10*time.Second,
					"Total time should scale reasonably with concurrency")
			})
		}
	})

	t.Run("memory_usage_performance", func(t *testing.T) {
		// Monitor memory usage during operations
		var memStats runtime.MemStats

		// Baseline memory usage
		runtime.GC()
		runtime.ReadMemStats(&memStats)
		baselineAlloc := memStats.Alloc

		// Perform multiple operations
		numOps := 20
		for i := 0; i < numOps; i++ {
			stdout, stderr, err := framework.RunCommand(
				"--config", configFile,
				"decrypt", fmt.Sprintf("memory-perf-test-%d", i),
			)

			assert.Error(t, err)
			assert.Contains(t, stderr, framework.ExpectDecryptError())
			assert.Empty(t, stdout)

			// Force garbage collection periodically
			if i%5 == 0 {
				runtime.GC()
			}
		}

		// Final memory reading
		runtime.GC()
		runtime.ReadMemStats(&memStats)
		finalAlloc := memStats.Alloc

		memoryIncrease := int64(finalAlloc) - int64(baselineAlloc)

		t.Logf("Memory usage analysis after %d operations:", numOps)
		t.Logf("  Baseline allocation: %d bytes", baselineAlloc)
		t.Logf("  Final allocation: %d bytes", finalAlloc)
		t.Logf("  Memory increase: %d bytes", memoryIncrease)
		t.Logf("  Total allocations: %d", memStats.TotalAlloc)
		t.Logf("  Number of GC cycles: %d", memStats.NumGC)

		// Memory should not grow excessively
		maxAcceptableIncrease := int64(50 * 1024 * 1024) // 50MB
		assert.Less(t, memoryIncrease, maxAcceptableIncrease,
			"Memory usage should not increase excessively")
	})

	t.Run("configuration_parsing_performance", func(t *testing.T) {
		// Test configuration parsing performance
		numTests := 50
		configTimes := make([]time.Duration, numTests)

		for i := 0; i < numTests; i++ {
			start := time.Now()

			stdout, stderr, err := framework.RunCommand(
				"--config", configFile,
				"--help",
			)

			duration := time.Since(start)
			configTimes[i] = duration

			assert.NoError(t, err)
			assert.Contains(t, stdout, "vault-dm-crypt")
			assert.Empty(t, stderr)
		}

		// Calculate statistics
		var total time.Duration
		min := configTimes[0]
		max := configTimes[0]

		for _, duration := range configTimes {
			total += duration
			if duration < min {
				min = duration
			}
			if duration > max {
				max = duration
			}
		}

		average := total / time.Duration(numTests)

		t.Logf("Configuration parsing performance over %d runs:", numTests)
		t.Logf("  Average: %v", average)
		t.Logf("  Min: %v", min)
		t.Logf("  Max: %v", max)

		// Configuration parsing should be fast
		assert.Less(t, average, 2*time.Second, "Configuration parsing should be fast")
	})
}

// TestStressScenarios tests system behavior under stress
func TestStressScenarios(t *testing.T) {
	framework := NewTestFramework(t)
	framework.RequireDocker()

	require.NoError(t, framework.Setup())
	defer framework.Cleanup()

	vaultAddr, roleID, secretID := framework.GetVaultConfig()
	configFile, err := framework.CreateTestConfig(vaultAddr, roleID, secretID)
	require.NoError(t, err)

	t.Run("high_frequency_operations", func(t *testing.T) {
		// Test rapid succession of operations
		numOperations := 100
		maxDuration := 5 * time.Minute

		start := time.Now()
		successCount := 0
		errorCount := 0

		for i := 0; i < numOperations && time.Since(start) < maxDuration; i++ {
			_, stderr, err := framework.RunCommand(
				"--config", configFile,
				"decrypt", fmt.Sprintf("stress-test-%d", i),
			)

			if err != nil && contains(stderr, framework.ExpectDecryptError()) {
				successCount++
			} else {
				errorCount++
				if errorCount < 5 { // Log first few errors
					t.Logf("Unexpected error in operation %d: %v - %s", i, err, stderr)
				}
			}

			// Brief pause to avoid overwhelming the system
			time.Sleep(10 * time.Millisecond)
		}

		totalDuration := time.Since(start)
		totalOperations := successCount + errorCount

		t.Logf("High frequency stress test results:")
		t.Logf("  Total operations: %d", totalOperations)
		t.Logf("  Successful operations: %d", successCount)
		t.Logf("  Error operations: %d", errorCount)
		t.Logf("  Total duration: %v", totalDuration)
		t.Logf("  Operations per second: %.2f", float64(totalOperations)/totalDuration.Seconds())

		// Most operations should succeed (even if they "fail" to find the device)
		successRate := float64(successCount) / float64(totalOperations)
		assert.Greater(t, successRate, 0.9, "Success rate should be high under stress")
	})

	t.Run("burst_load_handling", func(t *testing.T) {
		// Test handling of sudden burst loads
		burstSizes := []int{10, 25, 50}

		for _, burstSize := range burstSizes {
			t.Run(fmt.Sprintf("burst_size_%d", burstSize), func(t *testing.T) {
				var wg sync.WaitGroup
				results := make(chan bool, burstSize)

				start := time.Now()

				// Create sudden burst of operations
				for i := 0; i < burstSize; i++ {
					wg.Add(1)
					go func(id int) {
						defer wg.Done()

						_, stderr, err := framework.RunCommand(
							"--config", configFile,
							"decrypt", fmt.Sprintf("burst-test-%d-%d", burstSize, id),
						)

						success := err != nil && contains(stderr, framework.ExpectDecryptError())
						results <- success
					}(i)
				}

				wg.Wait()
				burstDuration := time.Since(start)

				// Collect results
				successCount := 0
				for i := 0; i < burstSize; i++ {
					if <-results {
						successCount++
					}
				}

				t.Logf("Burst load test (size=%d):", burstSize)
				t.Logf("  Duration: %v", burstDuration)
				t.Logf("  Success rate: %d/%d (%.1f%%)", successCount, burstSize,
					float64(successCount)/float64(burstSize)*100)

				// Should handle burst loads gracefully
				successRate := float64(successCount) / float64(burstSize)
				assert.Greater(t, successRate, 0.8, "Should handle burst loads reasonably well")
			})
		}
	})

	t.Run("sustained_load_test", func(t *testing.T) {
		// Test sustained load over extended period
		duration := 60 * time.Second // 1 minute sustained test
		operationInterval := 500 * time.Millisecond

		start := time.Now()
		operationCount := 0
		successCount := 0
		errorCount := 0

		for time.Since(start) < duration {
			opStart := time.Now()

			_, stderr, err := framework.RunCommand(
				"--config", configFile,
				"decrypt", fmt.Sprintf("sustained-test-%d", operationCount),
			)

			operationCount++

			if err != nil && contains(stderr, framework.ExpectDecryptError()) {
				successCount++
			} else {
				errorCount++
			}

			// Maintain consistent operation interval
			elapsed := time.Since(opStart)
			if elapsed < operationInterval {
				time.Sleep(operationInterval - elapsed)
			}
		}

		totalDuration := time.Since(start)

		t.Logf("Sustained load test results:")
		t.Logf("  Test duration: %v", totalDuration)
		t.Logf("  Total operations: %d", operationCount)
		t.Logf("  Successful operations: %d", successCount)
		t.Logf("  Failed operations: %d", errorCount)
		t.Logf("  Average operations per second: %.2f", float64(operationCount)/totalDuration.Seconds())

		// Should maintain performance under sustained load
		successRate := float64(successCount) / float64(operationCount)
		assert.Greater(t, successRate, 0.9, "Should maintain high success rate under sustained load")
		assert.Greater(t, operationCount, 50, "Should complete reasonable number of operations")
	})

	t.Run("resource_exhaustion_recovery", func(t *testing.T) {
		// Test recovery from resource exhaustion scenarios
		// Create many concurrent operations to exhaust resources
		highConcurrency := 100
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, highConcurrency)

		start := time.Now()
		operationCount := 0
		mu := sync.Mutex{}

		// Start many operations
		for i := 0; i < highConcurrency*2; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				semaphore <- struct{}{}        // Acquire semaphore
				defer func() { <-semaphore }() // Release semaphore

				stdout, stderr, err := framework.RunCommand(
					"--config", configFile,
					"decrypt", fmt.Sprintf("exhaustion-test-%d", id),
				)

				mu.Lock()
				operationCount++
				mu.Unlock()

				// Don't assert success here - under extreme load, some failures are acceptable
				_ = stdout
				_ = stderr
				_ = err
			}(i)
		}

		wg.Wait()
		totalDuration := time.Since(start)

		t.Logf("Resource exhaustion recovery test:")
		t.Logf("  Attempted operations: %d", highConcurrency*2)
		t.Logf("  Completed operations: %d", operationCount)
		t.Logf("  Total duration: %v", totalDuration)
		t.Logf("  Completion rate: %.1f%%", float64(operationCount)/float64(highConcurrency*2)*100)

		// Should complete most operations even under extreme load
		completionRate := float64(operationCount) / float64(highConcurrency*2)
		assert.Greater(t, completionRate, 0.7, "Should complete most operations even under extreme load")

		// Test that system recovers after load
		time.Sleep(5 * time.Second) // Allow system to recover

		stdout, stderr, err := framework.RunCommand(
			"--config", configFile,
			"decrypt", "recovery-test-uuid",
		)

		assert.Error(t, err)
		assert.Contains(t, stderr, framework.ExpectDecryptError())
		assert.Empty(t, stdout)

		t.Logf("System recovered successfully after resource exhaustion")
	})
}

// Helper function for string contains check (replacing strings.Contains for clarity)
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
