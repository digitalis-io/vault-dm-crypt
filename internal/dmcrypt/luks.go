package dmcrypt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"axonops/vault-dm-crypt/internal/errors"
)

// LUKSManager handles LUKS-specific operations
type LUKSManager struct {
	*Manager
	executor CommandExecutor
}

// NewLUKSManager creates a new LUKS manager
func NewLUKSManager(logger *logrus.Logger) *LUKSManager {
	manager := NewManager(logger)
	return &LUKSManager{
		Manager:  manager,
		executor: NewCommandExecutor(logger),
	}
}

// FormatDevice formats a device with LUKS encryption using the provided key and UUID
func (lm *LUKSManager) FormatDevice(devicePath, key, uuid string) error {
	lm.logger.WithFields(logrus.Fields{
		"device": devicePath,
		"uuid":   uuid,
	}).Info("Formatting device with LUKS")

	// Validate inputs
	if err := lm.ValidateDevice(devicePath); err != nil {
		return err
	}

	if err := lm.ValidateKeyFormat(key); err != nil {
		return errors.NewLUKSFailure(devicePath, "format", err)
	}

	// Check if device is mounted
	mounted, err := lm.IsDeviceMounted(devicePath)
	if err != nil {
		return errors.NewLUKSFailure(devicePath, "format", err)
	}

	if mounted {
		return errors.NewLUKSFailure(devicePath, "format", fmt.Errorf("device is currently mounted"))
	}

	// Decode the key
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return errors.NewLUKSFailure(devicePath, "format", fmt.Errorf("failed to decode key: %w", err))
	}

	// Create a temporary file for the key
	keyFile, err := lm.createTemporaryKeyFile(keyBytes)
	if err != nil {
		return errors.NewLUKSFailure(devicePath, "format", err)
	}
	defer lm.cleanupKeyFile(keyFile)

	// Prepare cryptsetup command
	args := []string{
		"luksFormat",
		"--type", "luks2", // Use LUKS2 format
		"--cipher", "aes-xts-plain64",
		"--key-size", "512", // 512-bit key
		"--hash", "sha256",
		"--iter-time", "2000", // 2 seconds iteration time
		"--uuid", uuid,
		"--key-file", keyFile,
		"--batch-mode", // Don't ask for confirmation
		devicePath,
	}

	lm.logger.WithFields(logrus.Fields{
		"device": devicePath,
		"uuid":   uuid,
		"cipher": "aes-xts-plain64",
	}).Debug("Executing cryptsetup luksFormat")

	// Execute cryptsetup
	output, err := lm.executor.Execute("cryptsetup", args...)
	if err != nil {
		return errors.NewLUKSFailure(devicePath, "format", fmt.Errorf("cryptsetup failed: %w (output: %s)", err, output))
	}

	lm.logger.WithFields(logrus.Fields{
		"device": devicePath,
		"uuid":   uuid,
	}).Info("Device successfully formatted with LUKS")

	return nil
}

// OpenDevice opens a LUKS-encrypted device using the provided key
func (lm *LUKSManager) OpenDevice(devicePath, key, deviceName string) error {
	lm.logger.WithFields(logrus.Fields{
		"device":      devicePath,
		"device_name": deviceName,
	}).Info("Opening LUKS device")

	// Validate inputs
	if err := lm.ValidateDevice(devicePath); err != nil {
		return err
	}

	if err := lm.ValidateKeyFormat(key); err != nil {
		return errors.NewLUKSFailure(devicePath, "open", err)
	}

	// Check if device is already open
	mappedPath := lm.GetMappedDevicePath(deviceName)
	if _, err := os.Stat(mappedPath); err == nil {
		lm.logger.WithField("mapped_device", mappedPath).Info("Device is already open")
		return nil
	}

	// Decode the key
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return errors.NewLUKSFailure(devicePath, "open", fmt.Errorf("failed to decode key: %w", err))
	}

	// Create a temporary file for the key
	keyFile, err := lm.createTemporaryKeyFile(keyBytes)
	if err != nil {
		return errors.NewLUKSFailure(devicePath, "open", err)
	}
	defer lm.cleanupKeyFile(keyFile)

	// Prepare cryptsetup command
	args := []string{
		"luksOpen",
		"--key-file", keyFile,
		devicePath,
		deviceName,
	}

	lm.logger.WithFields(logrus.Fields{
		"device":        devicePath,
		"device_name":   deviceName,
		"mapped_device": mappedPath,
	}).Debug("Executing cryptsetup luksOpen")

	// Execute cryptsetup
	output, err := lm.executor.Execute("cryptsetup", args...)
	if err != nil {
		return errors.NewLUKSFailure(devicePath, "open", fmt.Errorf("cryptsetup failed: %w (output: %s)", err, output))
	}

	// Verify the mapped device was created
	if _, err := os.Stat(mappedPath); err != nil {
		return errors.NewLUKSFailure(devicePath, "open", fmt.Errorf("mapped device not created: %s", mappedPath))
	}

	lm.logger.WithFields(logrus.Fields{
		"device":        devicePath,
		"device_name":   deviceName,
		"mapped_device": mappedPath,
	}).Info("LUKS device opened successfully")

	return nil
}

// CloseDevice closes a LUKS-encrypted device
func (lm *LUKSManager) CloseDevice(deviceName string) error {
	lm.logger.WithField("device_name", deviceName).Info("Closing LUKS device")

	// Check if device is open
	mappedPath := lm.GetMappedDevicePath(deviceName)
	if _, err := os.Stat(mappedPath); os.IsNotExist(err) {
		lm.logger.WithField("device_name", deviceName).Debug("Device is not open")
		return nil
	}

	// Prepare cryptsetup command
	args := []string{"luksClose", deviceName}

	lm.logger.WithFields(logrus.Fields{
		"device_name":   deviceName,
		"mapped_device": mappedPath,
	}).Debug("Executing cryptsetup luksClose")

	// Execute cryptsetup
	output, err := lm.executor.Execute("cryptsetup", args...)
	if err != nil {
		return errors.NewLUKSFailure(mappedPath, "close", fmt.Errorf("cryptsetup failed: %w (output: %s)", err, output))
	}

	lm.logger.WithField("device_name", deviceName).Info("LUKS device closed successfully")
	return nil
}

// IsLUKSDevice checks if a device is LUKS-formatted
func (lm *LUKSManager) IsLUKSDevice(devicePath string) (bool, error) {
	lm.logger.WithField("device", devicePath).Debug("Checking if device is LUKS-formatted")

	// Use cryptsetup isLuks to check
	args := []string{"isLuks", devicePath}

	_, err := lm.executor.Execute("cryptsetup", args...)
	if err != nil {
		// If cryptsetup returns non-zero exit code, it's not a LUKS device
		lm.logger.WithField("device", devicePath).Debug("Device is not LUKS-formatted")
		return false, nil
	}

	lm.logger.WithField("device", devicePath).Debug("Device is LUKS-formatted")
	return true, nil
}

// GetLUKSInfo retrieves information about a LUKS device
func (lm *LUKSManager) GetLUKSInfo(devicePath string) (map[string]string, error) {
	lm.logger.WithField("device", devicePath).Debug("Getting LUKS device information")

	// Check if it's a LUKS device first
	isLuks, err := lm.IsLUKSDevice(devicePath)
	if err != nil {
		return nil, err
	}

	if !isLuks {
		return nil, errors.NewLUKSFailure(devicePath, "info", fmt.Errorf("device is not LUKS-formatted"))
	}

	// Use cryptsetup luksDump to get information
	args := []string{"luksDump", devicePath}

	output, err := lm.executor.Execute("cryptsetup", args...)
	if err != nil {
		return nil, errors.NewLUKSFailure(devicePath, "info", fmt.Errorf("failed to get LUKS info: %w", err))
	}

	// Parse the output
	info := make(map[string]string)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for key-value pairs
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				info[key] = value
			}
		}
	}

	lm.logger.WithFields(logrus.Fields{
		"device":    devicePath,
		"info_keys": len(info),
	}).Debug("Retrieved LUKS device information")

	return info, nil
}

// createTemporaryKeyFile creates a temporary file containing the key
func (lm *LUKSManager) createTemporaryKeyFile(keyBytes []byte) (string, error) {
	// Create temporary file with restrictive permissions
	tmpFile, err := os.CreateTemp("", "vault-dm-crypt-key-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary key file: %w", err)
	}

	// Set restrictive permissions (readable only by owner)
	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to set key file permissions: %w", err)
	}

	// Write the key to the file
	if _, err := tmpFile.Write(keyBytes); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to write key to file: %w", err)
	}

	// Close the file
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to close key file: %w", err)
	}

	lm.logger.WithField("key_file", tmpFile.Name()).Debug("Created temporary key file")
	return tmpFile.Name(), nil
}

// cleanupKeyFile securely removes a temporary key file
func (lm *LUKSManager) cleanupKeyFile(keyFile string) {
	lm.logger.WithField("key_file", keyFile).Debug("Cleaning up temporary key file")

	// First, try to overwrite the file with random data
	if file, err := os.OpenFile(keyFile, os.O_WRONLY, 0); err == nil {
		// Get file size
		if stat, err := file.Stat(); err == nil {
			size := stat.Size()

			// Overwrite with random data
			if size > 0 {
				randomData := make([]byte, size)
				if _, err := io.ReadFull(rand.Reader, randomData); err == nil {
					file.WriteAt(randomData, 0)
					file.Sync()
				}
			}
		}
		file.Close()
	}

	// Remove the file
	if err := os.Remove(keyFile); err != nil {
		lm.logger.WithError(err).WithField("key_file", keyFile).Warn("Failed to remove temporary key file")
	} else {
		lm.logger.WithField("key_file", keyFile).Debug("Temporary key file removed")
	}
}
