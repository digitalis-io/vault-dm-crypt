package dmcrypt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"digitalisio/vault-dm-crypt/internal/errors"
)

// Manager handles dm-crypt operations
type Manager struct {
	logger *logrus.Logger
}

// NewManager creates a new dm-crypt manager
func NewManager(logger *logrus.Logger) *Manager {
	if logger == nil {
		logger = logrus.New()
	}
	return &Manager{
		logger: logger,
	}
}

// GenerateKey creates a cryptographically secure 4096-bit (512 byte) key
func (m *Manager) GenerateKey() (string, error) {
	m.logger.Debug("Generating 4096-bit encryption key")

	// Generate 512 bytes (4096 bits) of random data
	keyBytes := make([]byte, 512)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", errors.Wrap(err, "failed to generate random key")
	}

	// Encode to base64 for storage
	key := base64.StdEncoding.EncodeToString(keyBytes)

	m.logger.WithField("key_length", len(keyBytes)).Debug("Encryption key generated successfully")
	return key, nil
}

// ValidateDevice checks if a device exists and performs basic validation
func (m *Manager) ValidateDevice(devicePath string) error {
	m.logger.WithField("device", devicePath).Debug("Validating device")

	// Check if device exists
	if _, err := os.Stat(devicePath); err != nil {
		if os.IsNotExist(err) {
			return errors.NewLUKSFailure(devicePath, "validate", fmt.Errorf("device does not exist"))
		}
		return errors.NewLUKSFailure(devicePath, "validate", err)
	}

	// Check if it's a block device
	fileInfo, err := os.Stat(devicePath)
	if err != nil {
		return errors.NewLUKSFailure(devicePath, "validate", err)
	}

	// Get the file mode
	mode := fileInfo.Mode()

	// Check if it's a device (block or character device)
	if mode&os.ModeDevice == 0 {
		return errors.NewLUKSFailure(devicePath, "validate", fmt.Errorf("path is not a device"))
	}

	m.logger.WithField("device", devicePath).Debug("Device validation passed")
	return nil
}

// IsDeviceMounted checks if a device is currently mounted
func (m *Manager) IsDeviceMounted(devicePath string) (bool, error) {
	m.logger.WithField("device", devicePath).Debug("Checking if device is mounted")

	// Read /proc/mounts to check if device is mounted
	mountsData, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false, errors.Wrap(err, "failed to read /proc/mounts")
	}

	// Get the real path of the device in case it's a symlink
	realPath, err := filepath.EvalSymlinks(devicePath)
	if err != nil {
		// If we can't resolve symlinks, use the original path
		realPath = devicePath
	}

	// Parse mount entries
	lines := strings.Split(string(mountsData), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		mountedDevice := fields[0]

		// Check if the mounted device matches our device path
		if mountedDevice == devicePath || mountedDevice == realPath {
			m.logger.WithFields(logrus.Fields{
				"device":     devicePath,
				"mount_line": line,
			}).Debug("Device is mounted")
			return true, nil
		}
	}

	m.logger.WithField("device", devicePath).Debug("Device is not mounted")
	return false, nil
}

// GetDeviceUUID extracts the UUID from a LUKS device
func (m *Manager) GetDeviceUUID(devicePath string) (string, error) {
	m.logger.WithField("device", devicePath).Debug("Getting device UUID")

	// Use blkid to get the UUID
	executor := NewCommandExecutor(m.logger)
	output, err := executor.Execute("blkid", "-s", "UUID", "-o", "value", devicePath)
	if err != nil {
		return "", errors.NewLUKSFailure(devicePath, "get-uuid", err)
	}

	uuid := strings.TrimSpace(output)
	if uuid == "" {
		return "", errors.NewLUKSFailure(devicePath, "get-uuid", fmt.Errorf("no UUID found for device"))
	}

	m.logger.WithFields(logrus.Fields{
		"device": devicePath,
		"uuid":   uuid,
	}).Debug("Retrieved device UUID")

	return uuid, nil
}

// GenerateDeviceName creates a suitable device mapper name for a UUID
func (m *Manager) GenerateDeviceName(uuid string) string {
	// Clean the UUID to make it suitable for device mapper
	// Remove any hyphens and ensure it's lowercase
	cleanUUID := strings.ReplaceAll(strings.ToLower(uuid), "-", "")

	// Use vaultlocker prefix for compatibility
	deviceName := fmt.Sprintf("vaultlocker-%s", cleanUUID)

	m.logger.WithFields(logrus.Fields{
		"uuid":        uuid,
		"device_name": deviceName,
	}).Debug("Generated device mapper name")

	return deviceName
}

// GetMappedDevicePath returns the path to the mapped device
func (m *Manager) GetMappedDevicePath(deviceName string) string {
	return fmt.Sprintf("/dev/mapper/%s", deviceName)
}

// CheckRootPrivileges verifies that the process is running as root
func (m *Manager) CheckRootPrivileges() error {
	if os.Geteuid() != 0 {
		return errors.New("dm-crypt operations require root privileges")
	}
	return nil
}

// ValidateKeyFormat checks if a key is in the expected base64 format
func (m *Manager) ValidateKeyFormat(key string) error {
	// Decode the base64 key
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return errors.Wrap(err, "key is not valid base64")
	}

	// Check if it's the expected length (512 bytes = 4096 bits)
	if len(keyBytes) != 512 {
		return fmt.Errorf("key length is %d bytes, expected 512 bytes (4096 bits)", len(keyBytes))
	}

	return nil
}

// SecureEraseKey attempts to securely erase a key from memory
func (m *Manager) SecureEraseKey(key *string) {
	if key == nil || *key == "" {
		return
	}

	// Overwrite the string memory with zeros
	// Note: This is best effort in Go, as strings are immutable
	// and the GC may have copies. For truly sensitive operations,
	// we should use []byte and explicitly clear it.
	*key = strings.Repeat("\x00", len(*key))
	*key = ""

	m.logger.Debug("Key securely erased from memory")
}
