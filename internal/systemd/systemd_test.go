package systemd

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// MockExecutor implements the Executor interface for testing
type MockExecutor struct {
	commands []string
	outputs  map[string]string
	errors   map[string]error
}

func NewMockExecutor() *MockExecutor {
	return &MockExecutor{
		commands: make([]string, 0),
		outputs:  make(map[string]string),
		errors:   make(map[string]error),
	}
}

func (m *MockExecutor) Execute(command string, args ...string) (string, error) {
	key := command + " " + strings.Join(args, " ")
	m.commands = append(m.commands, key)

	if err, exists := m.errors[key]; exists {
		return "", err
	}

	if output, exists := m.outputs[key]; exists {
		return output, nil
	}

	return "", nil
}

func (m *MockExecutor) ExecuteWithTimeout(timeout time.Duration, command string, args ...string) (string, error) {
	return m.Execute(command, args...)
}

func (m *MockExecutor) ExecuteWithContext(ctx context.Context, command string, args ...string) (string, error) {
	return m.Execute(command, args...)
}

func (m *MockExecutor) IsCommandAvailable(command string) bool {
	if command == "systemctl" {
		return true
	}
	return false
}

func (m *MockExecutor) ValidateCommands(commands []string) error {
	return nil
}

func (m *MockExecutor) SetOutput(command string, output string) {
	m.outputs[command] = output
}

func (m *MockExecutor) SetError(command string, err error) {
	m.errors[command] = err
}

func (m *MockExecutor) GetExecutedCommands() []string {
	return m.commands
}

func TestNewManager(t *testing.T) {
	logger := logrus.New()
	manager := NewManager(logger)

	assert.NotNil(t, manager)
	assert.Equal(t, logger, manager.logger)
	assert.NotNil(t, manager.executor)
}

func TestEnableService(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs during tests

	manager := NewManager(logger)
	mockExecutor := NewMockExecutor()
	manager.executor = mockExecutor

	serviceName := "test-service.service"

	t.Run("successful enable", func(t *testing.T) {
		mockExecutor.SetOutput("systemctl enable "+serviceName, "")

		err := manager.EnableService(serviceName)
		assert.NoError(t, err)

		commands := mockExecutor.GetExecutedCommands()
		assert.Contains(t, commands, "systemctl enable "+serviceName)
	})

	t.Run("enable failure", func(t *testing.T) {
		mockExecutor.SetError("systemctl enable "+serviceName, fmt.Errorf("service not found"))

		err := manager.EnableService(serviceName)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to enable service")
	})
}

func TestDisableService(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)
	mockExecutor := NewMockExecutor()
	manager.executor = mockExecutor

	serviceName := "test-service.service"

	t.Run("successful disable", func(t *testing.T) {
		mockExecutor.SetOutput("systemctl disable "+serviceName, "")

		err := manager.DisableService(serviceName)
		assert.NoError(t, err)

		commands := mockExecutor.GetExecutedCommands()
		assert.Contains(t, commands, "systemctl disable "+serviceName)
	})

	t.Run("disable failure", func(t *testing.T) {
		mockExecutor.SetError("systemctl disable "+serviceName, fmt.Errorf("service not found"))

		err := manager.DisableService(serviceName)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to disable service")
	})
}

func TestStartService(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)
	mockExecutor := NewMockExecutor()
	manager.executor = mockExecutor

	serviceName := "test-service.service"

	err := manager.StartService(serviceName)
	assert.NoError(t, err)

	commands := mockExecutor.GetExecutedCommands()
	assert.Contains(t, commands, "systemctl start "+serviceName)
}

func TestStopService(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)
	mockExecutor := NewMockExecutor()
	manager.executor = mockExecutor

	serviceName := "test-service.service"

	err := manager.StopService(serviceName)
	assert.NoError(t, err)

	commands := mockExecutor.GetExecutedCommands()
	assert.Contains(t, commands, "systemctl stop "+serviceName)
}

func TestGetServiceStatus(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	serviceName := "test-service.service"

	t.Run("enabled and active service", func(t *testing.T) {
		manager := NewManager(logger)
		mockExecutor := NewMockExecutor()
		manager.executor = mockExecutor

		mockExecutor.SetOutput("systemctl is-enabled "+serviceName, "enabled")
		mockExecutor.SetOutput("systemctl is-active "+serviceName, "active")
		mockExecutor.SetOutput("systemctl is-failed "+serviceName, "active")

		status, err := manager.GetServiceStatus(serviceName)
		assert.NoError(t, err)
		assert.True(t, status.Enabled)
		assert.True(t, status.Active)
		assert.False(t, status.Failed)
		assert.Equal(t, serviceName, status.Name)
	})

	t.Run("disabled and inactive service", func(t *testing.T) {
		manager := NewManager(logger)
		mockExecutor := NewMockExecutor()
		manager.executor = mockExecutor

		mockExecutor.SetError("systemctl is-enabled "+serviceName, fmt.Errorf("disabled"))
		mockExecutor.SetError("systemctl is-active "+serviceName, fmt.Errorf("inactive"))
		mockExecutor.SetError("systemctl is-failed "+serviceName, fmt.Errorf("not failed"))

		status, err := manager.GetServiceStatus(serviceName)
		assert.NoError(t, err)
		assert.False(t, status.Enabled)
		assert.False(t, status.Active)
		assert.False(t, status.Failed)
	})

	t.Run("failed service", func(t *testing.T) {
		manager := NewManager(logger)
		mockExecutor := NewMockExecutor()
		manager.executor = mockExecutor

		mockExecutor.SetError("systemctl is-enabled "+serviceName, fmt.Errorf("disabled"))
		mockExecutor.SetError("systemctl is-active "+serviceName, fmt.Errorf("inactive"))
		mockExecutor.SetOutput("systemctl is-failed "+serviceName, "failed")

		status, err := manager.GetServiceStatus(serviceName)
		assert.NoError(t, err)
		assert.False(t, status.Enabled)
		assert.False(t, status.Active)
		assert.True(t, status.Failed)
	})
}

func TestReloadDaemon(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)
	mockExecutor := NewMockExecutor()
	manager.executor = mockExecutor

	err := manager.ReloadDaemon()
	assert.NoError(t, err)

	commands := mockExecutor.GetExecutedCommands()
	assert.Contains(t, commands, "systemctl daemon-reload")
}

func TestCreateDecryptServiceName(t *testing.T) {
	logger := logrus.New()
	manager := NewManager(logger)

	uuid := "12345678-1234-1234-1234-123456789abc"
	serviceName := manager.CreateDecryptServiceName(uuid)

	expected := "vault-dm-crypt-decrypt@12345678123412341234123456789abc.service"
	assert.Equal(t, expected, serviceName)
}

func TestEnableDecryptService(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)
	mockExecutor := NewMockExecutor()
	manager.executor = mockExecutor

	uuid := "12345678-1234-1234-1234-123456789abc"
	expectedServiceName := "vault-dm-crypt-decrypt@12345678123412341234123456789abc.service"

	err := manager.EnableDecryptService(uuid)
	assert.NoError(t, err)

	commands := mockExecutor.GetExecutedCommands()
	assert.Contains(t, commands, "systemctl enable "+expectedServiceName)
}

func TestDisableDecryptService(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)
	mockExecutor := NewMockExecutor()
	manager.executor = mockExecutor

	uuid := "12345678-1234-1234-1234-123456789abc"
	expectedServiceName := "vault-dm-crypt-decrypt@12345678123412341234123456789abc.service"

	err := manager.DisableDecryptService(uuid)
	assert.NoError(t, err)

	commands := mockExecutor.GetExecutedCommands()
	assert.Contains(t, commands, "systemctl disable "+expectedServiceName)
}

func TestValidateSystemdEnvironment(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)
	mockExecutor := NewMockExecutor()
	manager.executor = mockExecutor

	t.Run("valid systemd environment", func(t *testing.T) {
		mockExecutor.SetOutput("systemctl is-system-running", "running")
		mockExecutor.SetOutput("systemctl list-units --type=service --no-pager --no-legend --quiet", "")

		err := manager.ValidateSystemdEnvironment()
		assert.NoError(t, err)
	})

	t.Run("systemd communication failure", func(t *testing.T) {
		mockExecutor.SetError("systemctl list-units --type=service --no-pager --no-legend --quiet", fmt.Errorf("connection failed"))

		err := manager.ValidateSystemdEnvironment()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to communicate with systemd")
	})
}

func TestGetJournalLogs(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)
	mockExecutor := NewMockExecutor()
	manager.executor = mockExecutor

	serviceName := "test-service.service"
	lines := 50
	expectedOutput := "log line 1\nlog line 2\nlog line 3"

	mockExecutor.SetOutput("journalctl -u "+serviceName+" --no-pager -n 50", expectedOutput)

	output, err := manager.GetJournalLogs(serviceName, lines)
	assert.NoError(t, err)
	assert.Equal(t, expectedOutput, output)

	commands := mockExecutor.GetExecutedCommands()
	assert.Contains(t, commands, "journalctl -u "+serviceName+" --no-pager -n 50")
}

func TestListDecryptServices(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)
	mockExecutor := NewMockExecutor()
	manager.executor = mockExecutor

	t.Run("list services successfully", func(t *testing.T) {
		mockOutput := `vault-dm-crypt-decrypt@abcd1234.service loaded inactive dead Vault DM-Crypt Decrypt abcd1234
vault-dm-crypt-decrypt@efgh5678.service loaded active exited Vault DM-Crypt Decrypt efgh5678`

		mockExecutor.SetOutput("systemctl list-units --all --no-pager --no-legend vault-dm-crypt-decrypt@*.service", mockOutput)

		services, err := manager.ListDecryptServices()
		assert.NoError(t, err)
		assert.Len(t, services, 2)
		assert.Contains(t, services, "vault-dm-crypt-decrypt@abcd1234.service")
		assert.Contains(t, services, "vault-dm-crypt-decrypt@efgh5678.service")
	})

	t.Run("no services found", func(t *testing.T) {
		mockExecutor.SetOutput("systemctl list-units --all --no-pager --no-legend vault-dm-crypt-decrypt@*.service", "")

		services, err := manager.ListDecryptServices()
		assert.NoError(t, err)
		assert.Len(t, services, 0)
	})

	t.Run("systemctl command failure", func(t *testing.T) {
		mockExecutor.SetError("systemctl list-units --all --no-pager --no-legend vault-dm-crypt-decrypt@*.service", fmt.Errorf("command failed"))

		services, err := manager.ListDecryptServices()
		assert.Error(t, err)
		assert.Nil(t, services)
		assert.Contains(t, err.Error(), "failed to list decrypt services")
	})
}
