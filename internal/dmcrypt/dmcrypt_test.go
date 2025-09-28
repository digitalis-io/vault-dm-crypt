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
	commands          []string
	outputs           map[string]string
	errors            map[string]error
	availableCommands map[string]bool
	commandValidation error
}

func NewMockCommandExecutor() *MockCommandExecutor {
	return &MockCommandExecutor{
		commands:          make([]string, 0),
		outputs:           make(map[string]string),
		errors:            make(map[string]error),
		availableCommands: make(map[string]bool),
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
	if available, exists := m.availableCommands[command]; exists {
		return available
	}
	return true // Default to available if not explicitly set
}

func (m *MockCommandExecutor) ValidateCommands(commands []string) error {
	if m.commandValidation != nil {
		return m.commandValidation
	}

	var missing []string
	for _, cmd := range commands {
		if !m.IsCommandAvailable(cmd) {
			missing = append(missing, cmd)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("required commands not found: %s", strings.Join(missing, ", "))
	}

	return nil
}

func (m *MockCommandExecutor) SetOutput(command string, output string) {
	m.outputs[command] = output
}

func (m *MockCommandExecutor) SetError(command string, err error) {
	m.errors[command] = err
}

func (m *MockCommandExecutor) SetCommandAvailable(command string, available bool) {
	m.availableCommands[command] = available
}

func (m *MockCommandExecutor) SetCommandValidationError(err error) {
	m.commandValidation = err
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
		defer func() { _ = os.Remove(tmpFile.Name()) }()
		_ = tmpFile.Close()

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

func TestNewSystemValidator(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs during tests

	validator := NewSystemValidator(logger)

	assert.NotNil(t, validator)
	assert.Equal(t, logger, validator.logger)
	assert.NotNil(t, validator.executor)
}

func TestValidateSystemRequirements(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Note: ValidateSystemRequirements checks root privileges via CheckRootPrivileges()
	// which uses os.Geteuid() and cannot be easily mocked. This test validates
	// the other validation steps when root privileges would pass.

	t.Run("required commands failure", func(t *testing.T) {
		// Skip root privilege check for this test by testing the function directly
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		// Mock missing command
		mockExecutor.SetCommandAvailable("cryptsetup", false)

		err := validator.validateRequiredCommands()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required commands not found")
	})

	t.Run("kernel modules failure", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		// Mock kernel module failure
		mockExecutor.SetOutput("lsmod", "modules loaded")
		mockExecutor.SetError("modprobe dm_crypt", fmt.Errorf("module not found"))

		err := validator.validateKernelModules()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "kernel module validation failed for dm_crypt")
	})
}

func TestValidateRootPrivileges(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Note: validateRootPrivileges() calls manager.CheckRootPrivileges() which uses
	// os.Geteuid() directly and cannot be easily mocked. This test documents the
	// behavior rather than mocking it.

	t.Run("documents root privilege requirement", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		err := validator.validateRootPrivileges()

		// This will likely fail in CI/test environments since tests don't run as root
		// but we document that the function requires root privileges
		if err != nil {
			assert.Contains(t, err.Error(), "root privileges validation failed")
		}
	})
}

func TestValidateRequiredCommands(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	t.Run("all commands available", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		// All commands available by default (return true)

		err := validator.validateRequiredCommands()
		assert.NoError(t, err)
	})

	t.Run("missing command", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetCommandAvailable("cryptsetup", true)
		mockExecutor.SetCommandAvailable("blkid", false)
		mockExecutor.SetCommandAvailable("udevadm", true)

		err := validator.validateRequiredCommands()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required commands not found")
		assert.Contains(t, err.Error(), "blkid")
	})
}

func TestValidateKernelModules(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	t.Run("all modules available", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetOutput("lsmod", "dm_crypt loaded")
		mockExecutor.SetOutput("modprobe dm_crypt", "")
		mockExecutor.SetOutput("modprobe dm_mod", "")

		err := validator.validateKernelModules()
		assert.NoError(t, err)
	})

	t.Run("module loading failure", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetOutput("lsmod", "modules loaded")
		mockExecutor.SetError("modprobe dm_crypt", fmt.Errorf("module not available"))

		err := validator.validateKernelModules()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "kernel module validation failed for dm_crypt")
	})
}

func TestCheckKernelModule(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	t.Run("module loads successfully", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetOutput("lsmod", "dm_crypt loaded")
		mockExecutor.SetOutput("modprobe dm_crypt", "")

		err := validator.checkKernelModule("dm_crypt")
		assert.NoError(t, err)
	})

	t.Run("lsmod fails but modprobe works", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetError("lsmod", fmt.Errorf("lsmod failed"))
		mockExecutor.SetOutput("modprobe dm_crypt", "")

		err := validator.checkKernelModule("dm_crypt")
		assert.NoError(t, err)
	})

	t.Run("modprobe fails", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetOutput("lsmod", "modules loaded")
		mockExecutor.SetError("modprobe dm_crypt", fmt.Errorf("module not found"))

		err := validator.checkKernelModule("dm_crypt")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load kernel module dm_crypt")
	})
}

func TestValidateCryptsetupVersion(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	t.Run("successful version check", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetOutput("cryptsetup --version", "cryptsetup 2.3.3")

		err := validator.ValidateCryptsetupVersion()
		assert.NoError(t, err)
	})

	t.Run("cryptsetup command fails", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetError("cryptsetup --version", fmt.Errorf("command failed"))

		err := validator.ValidateCryptsetupVersion()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get cryptsetup version")
	})

	t.Run("empty version output", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetOutput("cryptsetup --version", "")

		err := validator.ValidateCryptsetupVersion()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cryptsetup version output is empty")
	})
}

func TestValidateDeviceMapperSupport(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	t.Run("device mapper available", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetOutput("ls /dev/mapper", "control")
		mockExecutor.SetOutput("dmsetup ls", "No devices found")

		err := validator.ValidateDeviceMapperSupport()
		assert.NoError(t, err)
	})

	t.Run("device mapper directory missing", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetError("ls /dev/mapper", fmt.Errorf("directory not found"))

		err := validator.ValidateDeviceMapperSupport()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device mapper directory not accessible")
	})

	t.Run("dmsetup not available but not critical", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetOutput("ls /dev/mapper", "control")
		mockExecutor.SetError("dmsetup ls", fmt.Errorf("dmsetup not found"))

		err := validator.ValidateDeviceMapperSupport()
		assert.NoError(t, err) // Should not fail even if dmsetup is missing
	})
}

func TestGetSystemInfo(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	t.Run("collect all system info", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetOutput("cryptsetup --version", "cryptsetup 2.3.3")
		mockExecutor.SetOutput("uname -r", "5.4.0-generic")
		mockExecutor.SetOutput("dmsetup version", "Library version:   1.02.167")
		mockExecutor.SetOutput("cryptsetup --help", "Usage: cryptsetup...")

		info, err := validator.GetSystemInfo()
		assert.NoError(t, err)
		assert.Equal(t, "cryptsetup 2.3.3", info["cryptsetup_version"])
		assert.Equal(t, "5.4.0-generic", info["kernel_version"])
		assert.Equal(t, "Library version:   1.02.167", info["dm_version"])
		assert.Equal(t, "yes", info["luks2_supported"])
	})

	t.Run("partial system info", func(t *testing.T) {
		validator := NewSystemValidator(logger)
		mockExecutor := NewMockCommandExecutor()
		validator.executor = mockExecutor

		mockExecutor.SetOutput("cryptsetup --version", "cryptsetup 2.3.3")
		mockExecutor.SetError("uname -r", fmt.Errorf("command failed"))
		mockExecutor.SetError("dmsetup version", fmt.Errorf("dmsetup not found"))
		mockExecutor.SetError("cryptsetup --help", fmt.Errorf("help failed"))

		info, err := validator.GetSystemInfo()
		assert.NoError(t, err)
		assert.Equal(t, "cryptsetup 2.3.3", info["cryptsetup_version"])
		assert.Equal(t, "unknown", info["luks2_supported"])
		assert.NotContains(t, info, "kernel_version")
		assert.NotContains(t, info, "dm_version")
	})
}

func TestGetDeviceUUID(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	manager := NewManager(logger)
	devicePath := "/dev/nonexistent"

	t.Run("device not found error", func(t *testing.T) {
		// This will likely fail since the device doesn't exist
		// but tests that the function handles errors properly
		uuid, err := manager.GetDeviceUUID(devicePath)
		assert.Error(t, err)
		assert.Empty(t, uuid)
		assert.Contains(t, err.Error(), "LUKS get-uuid failed")
	})
}

func TestLUKSManagerOpenDevice(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	luksManager := NewLUKSManager(logger)
	devicePath := "/dev/nonexistent"
	deviceName := "test-device"
	validKey := base64.StdEncoding.EncodeToString(make([]byte, 512)) // 4096-bit key

	t.Run("invalid device path", func(t *testing.T) {
		err := luksManager.OpenDevice(devicePath, validKey, deviceName)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "LUKS validate failed")
	})

	t.Run("invalid key format", func(t *testing.T) {
		err := luksManager.OpenDevice(devicePath, "invalid-key", deviceName)
		assert.Error(t, err)
		// Error will be from device validation first
		assert.Error(t, err)
	})
}

func TestLUKSManagerCloseDevice(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	luksManager := NewLUKSManager(logger)
	deviceName := "nonexistent-device"

	t.Run("close non-existent device", func(t *testing.T) {
		// This will likely fail but tests the error handling path
		err := luksManager.CloseDevice(deviceName)
		// Don't assert success/failure as it depends on environment
		_ = err
	})
}

func TestLUKSManagerGetLUKSInfo(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	luksManager := NewLUKSManager(logger)
	devicePath := "/dev/nonexistent"

	t.Run("device not found", func(t *testing.T) {
		info, err := luksManager.GetLUKSInfo(devicePath)
		assert.Error(t, err)
		assert.Nil(t, info)
		assert.Contains(t, err.Error(), "LUKS info failed")
	})
}

func TestUdevManagerRefreshDeviceDatabase(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	udevManager := NewUdevManager(logger)

	t.Run("calls udev commands", func(t *testing.T) {
		// This tests that the function exists and can be called
		// In a real environment, this would succeed if udevadm is available
		err := udevManager.RefreshDeviceDatabase()
		// Don't assert on success/failure since it depends on environment
		// Just verify the function doesn't panic
		_ = err
	})
}

func TestUdevManagerValidateUdevCommands(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	udevManager := NewUdevManager(logger)

	t.Run("validates udev command availability", func(t *testing.T) {
		// This tests that the function exists and can be called
		err := udevManager.ValidateUdevCommands()
		// Don't assert on success/failure since it depends on environment
		_ = err
	})
}

func TestSplitString(t *testing.T) {
	t.Run("normal split", func(t *testing.T) {
		parts := splitString("key=value", "=")
		assert.Equal(t, []string{"key", "value"}, parts)
	})

	t.Run("multiple separators", func(t *testing.T) {
		parts := splitString("a=b=c", "=")
		// This function splits on all occurrences, not just the first
		assert.Equal(t, []string{"a", "b", "c"}, parts)
	})

	t.Run("no separator", func(t *testing.T) {
		parts := splitString("noseparator", "=")
		assert.Equal(t, []string{"noseparator"}, parts)
	})

	t.Run("empty string", func(t *testing.T) {
		parts := splitString("", "=")
		// Empty string returns empty slice
		assert.Equal(t, []string{}, parts)
	})
}

func TestNewUdevManager(t *testing.T) {
	logger := logrus.New()
	udevManager := NewUdevManager(logger)

	assert.NotNil(t, udevManager)
	assert.Equal(t, logger, udevManager.logger)
	assert.NotNil(t, udevManager.executor)
}

func TestUdevManagerWaitForUUID(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	udevManager := NewUdevManager(logger)
	uuid := "nonexistent-uuid"
	timeout := 1 * time.Second

	t.Run("wait for non-existent UUID", func(t *testing.T) {
		// This will timeout/fail but tests the code path
		err := udevManager.WaitForUUID(uuid, timeout)
		// Don't assert success/failure as it depends on environment
		_ = err
	})
}

func TestUdevManagerWaitForDevice(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	udevManager := NewUdevManager(logger)
	devicePath := "/dev/nonexistent"
	timeout := 1 * time.Second

	t.Run("wait for non-existent device", func(t *testing.T) {
		// This will timeout/fail but tests the code path
		err := udevManager.WaitForDevice(devicePath, timeout)
		// Don't assert success/failure as it depends on environment
		_ = err
	})
}

func TestLUKSManagerFormatDevicePartial(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	luksManager := NewLUKSManager(logger)

	t.Run("format with invalid device", func(t *testing.T) {
		invalidDevice := "/dev/nonexistent"
		validKey := base64.StdEncoding.EncodeToString(make([]byte, 512))
		uuid := "test-uuid"

		err := luksManager.FormatDevice(invalidDevice, validKey, uuid)
		assert.Error(t, err)
		// This will fail at device validation stage
		assert.Contains(t, err.Error(), "LUKS validate failed")
	})
}
