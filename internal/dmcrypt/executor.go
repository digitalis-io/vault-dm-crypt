package dmcrypt

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/axonops/vault-dm-crypt/internal/shell"
)

// CommandExecutor interface for executing system commands
type CommandExecutor interface {
	Execute(command string, args ...string) (string, error)
	ExecuteWithTimeout(timeout time.Duration, command string, args ...string) (string, error)
	ExecuteWithContext(ctx context.Context, command string, args ...string) (string, error)
	IsCommandAvailable(command string) bool
	ValidateCommands(commands []string) error
}

// NewCommandExecutor creates a new command executor
func NewCommandExecutor(logger *logrus.Logger) CommandExecutor {
	return shell.NewExecutor(logger)
}
