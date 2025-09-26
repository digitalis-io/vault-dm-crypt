package errors

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVaultlockerError(t *testing.T) {
	t.Run("basic error", func(t *testing.T) {
		err := New("test error")
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("empty message", func(t *testing.T) {
		err := &VaultlockerError{}
		assert.Equal(t, "Vaultlocker Error", err.Error())
	})

	t.Run("wrapped error", func(t *testing.T) {
		baseErr := errors.New("base error")
		err := Wrap(baseErr, "wrapped")
		assert.Equal(t, "wrapped: base error", err.Error())
		assert.Equal(t, baseErr, err.Unwrap())
	})
}

func TestVaultWriteError(t *testing.T) {
	baseErr := errors.New("network error")
	err := NewVaultWriteError("/secret/test", baseErr)

	assert.Equal(t, "Failed to write to vault path /secret/test: network error", err.Error())
	assert.Equal(t, baseErr, err.Unwrap())
}

func TestVaultReadError(t *testing.T) {
	baseErr := errors.New("not found")
	err := NewVaultReadError("/secret/missing", baseErr)

	assert.Equal(t, "Failed to read from vault path /secret/missing: not found", err.Error())
	assert.Equal(t, baseErr, err.Unwrap())
}

func TestVaultDeleteError(t *testing.T) {
	baseErr := errors.New("permission denied")
	err := NewVaultDeleteError("/secret/delete", baseErr)

	assert.Equal(t, "Failed to delete vault key at path /secret/delete: permission denied", err.Error())
	assert.Equal(t, baseErr, err.Unwrap())
}

func TestVaultKeyMismatch(t *testing.T) {
	err := NewVaultKeyMismatch("/secret/mismatch")
	assert.Equal(t, "Vault key does not match generated key at path /secret/mismatch", err.Error())
}

func TestLUKSFailure(t *testing.T) {
	baseErr := errors.New("device busy")
	err := NewLUKSFailure("/dev/sda1", "format", baseErr)

	assert.Equal(t, "LUKS format failed on device /dev/sda1: device busy", err.Error())
	assert.Equal(t, baseErr, err.Unwrap())
}

func TestConfigError(t *testing.T) {
	t.Run("with field", func(t *testing.T) {
		err := NewConfigError("vault.url", "invalid URL format", nil)
		assert.Equal(t, "Configuration error in field 'vault.url': invalid URL format", err.Error())
	})

	t.Run("without field", func(t *testing.T) {
		err := NewConfigError("", "general config error", nil)
		assert.Equal(t, "Configuration error: general config error", err.Error())
	})

	t.Run("with cause", func(t *testing.T) {
		baseErr := errors.New("parse error")
		err := NewConfigError("logging.level", "invalid level", baseErr)
		assert.Equal(t, "Configuration error in field 'logging.level': invalid level", err.Error())
		assert.Equal(t, baseErr, err.Unwrap())
	})
}
