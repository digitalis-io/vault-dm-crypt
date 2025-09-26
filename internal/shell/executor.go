package shell

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Executor handles command execution with proper logging and error handling
type Executor struct {
	logger *logrus.Logger
}

// NewExecutor creates a new command executor
func NewExecutor(logger *logrus.Logger) *Executor {
	if logger == nil {
		logger = logrus.New()
	}
	return &Executor{logger: logger}
}

// Execute runs a command with the given arguments
func (e *Executor) Execute(command string, args ...string) (string, error) {
	return e.ExecuteWithTimeout(30*time.Second, command, args...)
}

// ExecuteWithTimeout runs a command with a specific timeout
func (e *Executor) ExecuteWithTimeout(timeout time.Duration, command string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return e.ExecuteWithContext(ctx, command, args...)
}

// ExecuteWithContext runs a command with a given context
func (e *Executor) ExecuteWithContext(ctx context.Context, command string, args ...string) (string, error) {
	e.logger.WithFields(logrus.Fields{
		"command": command,
		"args":    args,
	}).Debug("Executing command")

	// Create the command
	cmd := exec.CommandContext(ctx, command, args...)

	// Capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command
	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	// Get output
	stdoutStr := stdout.String()
	stderrStr := stderr.String()

	// Log the execution result
	logFields := logrus.Fields{
		"command":  command,
		"args":     args,
		"duration": duration,
		"stdout":   stdoutStr,
		"stderr":   stderrStr,
	}

	if err != nil {
		// Check if it's a context timeout
		if ctx.Err() == context.DeadlineExceeded {
			e.logger.WithFields(logFields).Error("Command execution timed out")
			return "", fmt.Errorf("command timed out after %v: %s %s", duration, command, strings.Join(args, " "))
		}

		// Check if it's an exit error
		if exitError, ok := err.(*exec.ExitError); ok {
			e.logger.WithFields(logFields).WithField("exit_code", exitError.ExitCode()).Error("Command failed")
			return "", fmt.Errorf("command failed with exit code %d: %s (stderr: %s)", exitError.ExitCode(), command, stderrStr)
		}

		e.logger.WithFields(logFields).WithError(err).Error("Command execution failed")
		return "", fmt.Errorf("command execution failed: %w", err)
	}

	e.logger.WithFields(logFields).Debug("Command executed successfully")
	return stdoutStr, nil
}

// ExecuteQuiet runs a command without detailed logging (for sensitive operations)
func (e *Executor) ExecuteQuiet(command string, args ...string) (string, error) {
	e.logger.WithField("command", command).Debug("Executing command (quiet mode)")

	cmd := exec.Command(command, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	stdoutStr := stdout.String()

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("command failed with exit code %d: %s", exitError.ExitCode(), command)
		}
		return "", fmt.Errorf("command execution failed: %w", err)
	}

	e.logger.WithField("command", command).Debug("Command executed successfully (quiet mode)")
	return stdoutStr, nil
}

// IsCommandAvailable checks if a command is available in the system PATH
func (e *Executor) IsCommandAvailable(command string) bool {
	_, err := exec.LookPath(command)
	available := err == nil

	e.logger.WithFields(logrus.Fields{
		"command":   command,
		"available": available,
	}).Debug("Checked command availability")

	return available
}

// ValidateCommands checks if all required commands are available
func (e *Executor) ValidateCommands(commands []string) error {
	var missing []string

	for _, cmd := range commands {
		if !e.IsCommandAvailable(cmd) {
			missing = append(missing, cmd)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("required commands not found: %s", strings.Join(missing, ", "))
	}

	e.logger.WithField("commands", commands).Debug("All required commands are available")
	return nil
}