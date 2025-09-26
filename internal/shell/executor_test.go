package shell

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewExecutor(t *testing.T) {
	logger := logrus.New()
	executor := NewExecutor(logger)

	assert.NotNil(t, executor)
	assert.Equal(t, logger, executor.logger)
}

func TestNewExecutorNilLogger(t *testing.T) {
	executor := NewExecutor(nil)

	assert.NotNil(t, executor)
	assert.NotNil(t, executor.logger)
}

func TestExecute(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs during tests
	executor := NewExecutor(logger)

	t.Run("successful command", func(t *testing.T) {
		output, err := executor.Execute("echo", "hello world")
		assert.NoError(t, err)
		assert.Contains(t, output, "hello world")
	})

	t.Run("command with no output", func(t *testing.T) {
		output, err := executor.Execute("true")
		assert.NoError(t, err)
		assert.Empty(t, output)
	})

	t.Run("failing command", func(t *testing.T) {
		output, err := executor.Execute("false")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exit code 1")
		assert.Empty(t, output)
	})

	t.Run("non-existent command", func(t *testing.T) {
		output, err := executor.Execute("non-existent-command-12345")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "command execution failed")
		assert.Empty(t, output)
	})
}

func TestExecuteWithTimeout(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	executor := NewExecutor(logger)

	t.Run("command completes within timeout", func(t *testing.T) {
		output, err := executor.ExecuteWithTimeout(5*time.Second, "echo", "test")
		assert.NoError(t, err)
		assert.Contains(t, output, "test")
	})

	t.Run("command times out", func(t *testing.T) {
		// Use sleep command that will exceed timeout
		output, err := executor.ExecuteWithTimeout(100*time.Millisecond, "sleep", "1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timed out")
		assert.Empty(t, output)
	})
}

func TestExecuteWithContext(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	executor := NewExecutor(logger)

	t.Run("successful execution", func(t *testing.T) {
		ctx := context.Background()
		output, err := executor.ExecuteWithContext(ctx, "echo", "test")
		assert.NoError(t, err)
		assert.Contains(t, output, "test")
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		output, err := executor.ExecuteWithContext(ctx, "sleep", "1")
		assert.Error(t, err)
		assert.Empty(t, output)
	})

	t.Run("context with timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		output, err := executor.ExecuteWithContext(ctx, "sleep", "1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timed out")
		assert.Empty(t, output)
	})
}

func TestExecuteQuiet(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	executor := NewExecutor(logger)

	t.Run("successful quiet execution", func(t *testing.T) {
		output, err := executor.ExecuteQuiet("echo", "quiet test")
		assert.NoError(t, err)
		assert.Contains(t, output, "quiet test")
	})

	t.Run("failing quiet execution", func(t *testing.T) {
		output, err := executor.ExecuteQuiet("false")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exit code 1")
		assert.Empty(t, output)
	})
}

func TestIsCommandAvailable(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	executor := NewExecutor(logger)

	t.Run("available command", func(t *testing.T) {
		// Test with a command that should be available on most systems
		available := executor.IsCommandAvailable("echo")
		assert.True(t, available)
	})

	t.Run("unavailable command", func(t *testing.T) {
		available := executor.IsCommandAvailable("non-existent-command-xyz-123")
		assert.False(t, available)
	})
}

func TestValidateCommands(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	executor := NewExecutor(logger)

	t.Run("all commands available", func(t *testing.T) {
		commands := []string{"echo", "true", "false"}
		err := executor.ValidateCommands(commands)
		assert.NoError(t, err)
	})

	t.Run("some commands missing", func(t *testing.T) {
		commands := []string{"echo", "non-existent-cmd-1", "non-existent-cmd-2"}
		err := executor.ValidateCommands(commands)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required commands not found")
		assert.Contains(t, err.Error(), "non-existent-cmd-1")
		assert.Contains(t, err.Error(), "non-existent-cmd-2")
	})

	t.Run("empty command list", func(t *testing.T) {
		commands := []string{}
		err := executor.ValidateCommands(commands)
		assert.NoError(t, err)
	})
}