package errors

import (
	"fmt"
)

// VaultlockerError is the base error type for all vaultlocker errors
type VaultlockerError struct {
	message string
	cause   error
}

// Error implements the error interface
func (e *VaultlockerError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.message, e.cause)
	}
	if e.message != "" {
		return e.message
	}
	return "Vaultlocker Error"
}

// Unwrap returns the underlying error
func (e *VaultlockerError) Unwrap() error {
	return e.cause
}

// New creates a new VaultlockerError
func New(message string) *VaultlockerError {
	return &VaultlockerError{message: message}
}

// Wrap wraps an error with a VaultlockerError
func Wrap(err error, message string) *VaultlockerError {
	return &VaultlockerError{message: message, cause: err}
}

// VaultWriteError indicates failure to write to vault
type VaultWriteError struct {
	Path  string
	Cause error
}

// Error implements the error interface
func (e *VaultWriteError) Error() string {
	return fmt.Sprintf("Failed to write to vault path %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying error
func (e *VaultWriteError) Unwrap() error {
	return e.Cause
}

// NewVaultWriteError creates a new VaultWriteError
func NewVaultWriteError(path string, cause error) *VaultWriteError {
	return &VaultWriteError{Path: path, Cause: cause}
}

// VaultReadError indicates failure to read from vault
type VaultReadError struct {
	Path  string
	Cause error
}

// Error implements the error interface
func (e *VaultReadError) Error() string {
	return fmt.Sprintf("Failed to read from vault path %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying error
func (e *VaultReadError) Unwrap() error {
	return e.Cause
}

// NewVaultReadError creates a new VaultReadError
func NewVaultReadError(path string, cause error) *VaultReadError {
	return &VaultReadError{Path: path, Cause: cause}
}

// VaultDeleteError indicates failure to delete from vault
type VaultDeleteError struct {
	Path  string
	Cause error
}

// Error implements the error interface
func (e *VaultDeleteError) Error() string {
	return fmt.Sprintf("Failed to delete vault key at path %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying error
func (e *VaultDeleteError) Unwrap() error {
	return e.Cause
}

// NewVaultDeleteError creates a new VaultDeleteError
func NewVaultDeleteError(path string, cause error) *VaultDeleteError {
	return &VaultDeleteError{Path: path, Cause: cause}
}

// VaultKeyMismatch indicates vault key doesn't match generated key
type VaultKeyMismatch struct {
	Path string
}

// Error implements the error interface
func (e *VaultKeyMismatch) Error() string {
	return fmt.Sprintf("Vault key does not match generated key at path %s", e.Path)
}

// NewVaultKeyMismatch creates a new VaultKeyMismatch error
func NewVaultKeyMismatch(path string) *VaultKeyMismatch {
	return &VaultKeyMismatch{Path: path}
}

// LUKSFailure represents errors when operating on a block device
type LUKSFailure struct {
	Device string
	Op     string
	Cause  error
}

// Error implements the error interface
func (e *LUKSFailure) Error() string {
	return fmt.Sprintf("LUKS %s failed on device %s: %v", e.Op, e.Device, e.Cause)
}

// Unwrap returns the underlying error
func (e *LUKSFailure) Unwrap() error {
	return e.Cause
}

// NewLUKSFailure creates a new LUKSFailure error
func NewLUKSFailure(device, operation string, cause error) *LUKSFailure {
	return &LUKSFailure{Device: device, Op: operation, Cause: cause}
}

// ConfigError represents configuration-related errors
type ConfigError struct {
	Field   string
	Message string
	Cause   error
}

// Error implements the error interface
func (e *ConfigError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("Configuration error in field '%s': %s", e.Field, e.Message)
	}
	return fmt.Sprintf("Configuration error: %s", e.Message)
}

// Unwrap returns the underlying error
func (e *ConfigError) Unwrap() error {
	return e.Cause
}

// NewConfigError creates a new ConfigError
func NewConfigError(field, message string, cause error) *ConfigError {
	return &ConfigError{Field: field, Message: message, Cause: cause}
}
