package dmcrypt

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockCommandExecutor implements CommandExecutor for testing
type MockCommandExecutor struct {
	commands []string
	outputs  map[string]string
	errors   map[string]error
}

func NewMockCommandExecutor() *MockCommandExecutor {
	return &MockCommandExecutor{
		commands: make([]string, 0),
		outputs:  make(map[string]string),
		errors:   make(map[string]error),
	}
}

func (m *MockCommandExecutor) Execute(command string, args ...string) (string, error) {
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

func (m *MockCommandExecutor) ExecuteWithTimeout(timeout time.Duration, command string, args ...string) (string, error) {
	return m.Execute(command, args...)
}

func (m *MockCommandExecutor) ExecuteWithContext(ctx context.Context, command string, args ...string) (string, error) {
	return m.Execute(command, args...)
}

func (m *MockCommandExecutor) IsCommandAvailable(command string) bool {
	return true
}

func (m *MockCommandExecutor) ValidateCommands(commands []string) error {
	return nil
}

func (m *MockCommandExecutor) SetOutput(command string, output string) {
	m.outputs[command] = output
}

func (m *MockCommandExecutor) SetError(command string, err error) {
	m.errors[command] = err
}

func (m *MockCommandExecutor) GetExecutedCommands() []string {
	return m.commands
}

func TestNewManager(t *testing.T) {
	logger := logrus.New()
	manager := NewManager(logger)

	assert.NotNil(t, manager)
	assert.Equal(t, logger, manager.logger)
}

func TestGenerateKey(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs during tests

	manager := NewManager(logger)

	key, err := manager.GenerateKey()
	require.NoError(t, err)
	assert.NotEmpty(t, key)

	// Verify it's valid base64
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	require.NoError(t, err)

	// Verify it's the correct length (512 bytes = 4096 bits)
	assert.Equal(t, 512, len(keyBytes))

	// Verify multiple keys are different
	key2, err := manager.GenerateKey()
	require.NoError(t, err)
	assert.NotEqual(t, key, key2)
}

func TestValidateDevice(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)

	t.Run("existing device", func(t *testing.T) {
		// Create a temporary file to simulate a device
		tmpFile, err := os.CreateTemp("", "test-device-*")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		err = manager.ValidateDevice(tmpFile.Name())
		// This will fail because it's not actually a device, but the file exists
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not a device")
	})

	t.Run("non-existing device", func(t *testing.T) {
		err := manager.ValidateDevice("/non/existent/device")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device does not exist")
	})
}

func TestValidateKeyFormat(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)

	t.Run("valid key", func(t *testing.T) {
		// Generate a valid key
		key, err := manager.GenerateKey()
		require.NoError(t, err)

		err = manager.ValidateKeyFormat(key)
		assert.NoError(t, err)
	})

	t.Run("invalid base64", func(t *testing.T) {
		err := manager.ValidateKeyFormat("invalid-base64-!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not valid base64")
	})

	t.Run("wrong length", func(t *testing.T) {
		// Create a key with wrong length (100 bytes instead of 512)
		shortKey := make([]byte, 100)
		key := base64.StdEncoding.EncodeToString(shortKey)

		err := manager.ValidateKeyFormat(key)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key length is 100 bytes, expected 512 bytes")
	})
}

func TestGenerateDeviceName(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)

	uuid := "12345678-1234-1234-1234-123456789abc"
	deviceName := manager.GenerateDeviceName(uuid)

	assert.Equal(t, "vaultlocker-12345678123412341234123456789abc", deviceName)
	assert.True(t, strings.HasPrefix(deviceName, "vaultlocker-"))
}

func TestGetMappedDevicePath(t *testing.T) {
	logger := logrus.New()
	manager := NewManager(logger)

	deviceName := "test-device"
	mappedPath := manager.GetMappedDevicePath(deviceName)

	assert.Equal(t, "/dev/mapper/test-device", mappedPath)
}

func TestSecureEraseKey(t *testing.T) {
	logger := logrus.New()
	manager := NewManager(logger)

	key := "sensitive-key-data"
	manager.SecureEraseKey(&key)

	assert.Empty(t, key)
}

func TestIsDeviceMounted(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)

	// Test with a non-existent device
	mounted, err := manager.IsDeviceMounted("/dev/non-existent")
	assert.NoError(t, err)
	assert.False(t, mounted)
}

func TestCheckRootPrivileges(t *testing.T) {
	logger := logrus.New()
	manager := NewManager(logger)

	err := manager.CheckRootPrivileges()
	// This will likely fail in test environment since we're not root
	// but we can test the function exists and returns an error
	if os.Geteuid() != 0 {
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "root privileges")
	} else {
		assert.NoError(t, err)
	}
}

func TestNewLUKSManager(t *testing.T) {
	logger := logrus.New()
	luksManager := NewLUKSManager(logger)

	assert.NotNil(t, luksManager)
	assert.NotNil(t, luksManager.Manager)
	assert.NotNil(t, luksManager.executor)
}

func TestLUKSManagerFormatDevice(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	luksManager := NewLUKSManager(logger)
	mockExecutor := NewMockCommandExecutor()
	luksManager.executor = mockExecutor

	// Generate a valid key
	key, err := luksManager.GenerateKey()
	require.NoError(t, err)

	uuid := "12345678-1234-1234-1234-123456789abc"

	t.Run("invalid device", func(t *testing.T) {
		err := luksManager.FormatDevice("/non/existent/device", key, uuid)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device does not exist")
	})

	t.Run("invalid key", func(t *testing.T) {
		// Test with a non-existent device since device validation comes first
		err := luksManager.FormatDevice("/dev/null", "invalid-key", uuid)
		assert.Error(t, err)
		// The error could be either device validation or key validation
		assert.True(t,
			strings.Contains(err.Error(), "not valid base64") ||
			strings.Contains(err.Error(), "not a device"))
	})
}

func TestLUKSManagerIsLUKSDevice(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	luksManager := NewLUKSManager(logger)
	mockExecutor := NewMockCommandExecutor()
	luksManager.executor = mockExecutor

	devicePath := "/dev/test"

	t.Run("is LUKS device", func(t *testing.T) {
		// Set up mock to return success (exit code 0)
		mockExecutor.SetOutput("cryptsetup isLuks "+devicePath, "")

		isLuks, err := luksManager.IsLUKSDevice(devicePath)
		assert.NoError(t, err)
		assert.True(t, isLuks)
	})

	t.Run("is not LUKS device", func(t *testing.T) {
		// Set up mock to return error (non-zero exit code)
		mockExecutor.SetError("cryptsetup isLuks "+devicePath, fmt.Errorf("exit code 1"))

		isLuks, err := luksManager.IsLUKSDevice(devicePath)
		assert.NoError(t, err)
		assert.False(t, isLuks)
	})
}

func TestUdevManager(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	udevManager := NewUdevManager(logger)
	mockExecutor := NewMockCommandExecutor()
	udevManager.executor = mockExecutor

	devicePath := "/dev/test"

	t.Run("trigger rescan", func(t *testing.T) {
		err := udevManager.TriggerRescan(devicePath)
		assert.NoError(t, err)

		commands := mockExecutor.GetExecutedCommands()
		assert.Contains(t, commands, "udevadm trigger --action=change "+devicePath)
	})

	t.Run("wait for settle", func(t *testing.T) {
		timeout := 5 * time.Second
		err := udevManager.WaitForSettle(timeout)
		assert.NoError(t, err)

		commands := mockExecutor.GetExecutedCommands()
		assert.Contains(t, commands, "udevadm settle --timeout=5")
	})

	t.Run("get device info", func(t *testing.T) {
		mockOutput := "DEVTYPE=disk\nID_FS_TYPE=crypto_LUKS\nID_FS_UUID=test-uuid\n"
		mockExecutor.SetOutput("udevadm info --query=property --name "+devicePath, mockOutput)

		info, err := udevManager.GetDeviceInfo(devicePath)
		assert.NoError(t, err)
		assert.Equal(t, "disk", info["DEVTYPE"])
		assert.Equal(t, "crypto_LUKS", info["ID_FS_TYPE"])
		assert.Equal(t, "test-uuid", info["ID_FS_UUID"])
	})
}

func TestHelperFunctions(t *testing.T) {
	t.Run("splitLines", func(t *testing.T) {
		input := "line1\nline2\n\nline3\n"
		lines := splitLines(input)
		assert.Equal(t, []string{"line1", "line2", "line3"}, lines)
	})

	t.Run("splitKeyValue", func(t *testing.T) {
		key, value, found := splitKeyValue("KEY=VALUE", "=")
		assert.True(t, found)
		assert.Equal(t, "KEY", key)
		assert.Equal(t, "VALUE", value)

		key, value, found = splitKeyValue("NOEQUALS", "=")
		assert.False(t, found)
		assert.Empty(t, key)
		assert.Empty(t, value)
	})

	t.Run("trimSpace", func(t *testing.T) {
		assert.Equal(t, "test", trimSpace("  test  "))
		assert.Equal(t, "test", trimSpace("\ttest\n"))
		assert.Equal(t, "", trimSpace("   "))
	})
}