# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4-alpha] - 2025-12-31

### Added

- **CLI Wipe Command Options**
  - `--full` - Wipe entire device instead of headers only
  - `--passes N` - Multi-pass overwrite support
  - `--random` - Use random data instead of zeros
  - `--trim` - Issue TRIM/DISCARD after wipe for SSDs

- **Unit Tests**
  - Added 9 new CLI unit tests for wipe command options

### Changed

- **Documentation Overhaul**
  - Complete README rewrite with concise, accurate API documentation
  - Added Recovery Key API documentation (GenerateRecoveryKey, AddRecoveryKey, etc.)
  - Added Filesystem utilities (CheckFilesystem, GetFilesystemInfo, SupportedFilesystems)
  - Added Header validation functions (IsLUKS, IsLUKS2, WriteHeader)
  - Updated CLI wipe documentation with new options

## [0.1.3-alpha] - 2025-12-31

### Added

- **Cryptsetup Compatibility**
  - `IsLUKS()` - Check if device contains any LUKS header (v1 or v2)
  - `IsLUKS2()` - Check if device contains a LUKS2 header specifically
  - `TestKey()` - Verify passphrase without unlocking (like `cryptsetup luksOpen --test-passphrase`)
  - `KillSlot()` - Remove keyslot using any valid passphrase (like `cryptsetup luksKillSlot`)

- **LUKS2 Header Constants** (matching cryptsetup defaults)
  - `LUKS2HeaderMinSize`, `LUKS2HeaderDefaultSize`, `LUKS2MaxKeyslotsSize`, `LUKS2MaxKeyslots`
  - `LUKS2DefaultKeyslotsSize` - 16 MiB default keyslots area

- **Device Handling Improvements**
  - Symlink resolution for device paths (dm-crypt requires actual block device)
  - `waitForDeviceReady()` for udev compatibility in containerized environments
  - Keyslot overlap protection when adding keys

### Changed

- Format now uses cryptsetup-compatible 16 MiB default metadata area
- Removed all debug `fmt.Fprintf` statements from library code
- Library returns errors instead of logging; added `SaveError` field to `RecoveryKey`

### Fixed

- Fixed gosec G115 integer overflow warnings in device-mapper code
- Fixed gosec G301 directory permissions (0755 → 0750)
- Fixed `TestSmallVolumeMinimumSize` minimum volume size (16MB → 32MB)

## [0.1.2-alpha] - 2025-12-22

### Added

- **Token Management API**
  - New `Token` type with support for FIDO2 and TPM2 tokens
  - Functions: `GetToken`, `ListTokens`, `ImportToken`, `ImportTokenJSON`, `ExportToken`, `RemoveToken`, `FindFreeTokenSlot`, `TokenExists`, `CountTokens`
  - Full LUKS2 token slot management (slots 0-31)

- **DevContainer Support**
  - Added `.devcontainer/` configuration for VS Code development
  - Privileged container setup for LUKS operations during development
  - Pre-configured Go tools (gopls, delve, golangci-lint, gosec)

- **CLI Testability Refactoring**
  - Dependency injection interfaces: `LuksOperations`, `Terminal`, `FileSystem`
  - Comprehensive CLI unit tests with mock implementations
  - Separated CLI logic from main.go for better testability

- **Integration Test Reorganization**
  - New `test/integration/pkg/` for package-level integration tests
  - New `test/integration/cli/` for CLI integration tests
  - Common test helpers in `test/integration/pkg/common_test.go`

- **Additional Unit Tests**
  - `pkg/luks2/format_test.go` - encrypt/decrypt key material tests
  - `pkg/luks2/mount_test.go` - mount operation tests
  - `pkg/luks2/unlock_test.go` - unlock helper function tests

### Changed

- Updated Makefile with new targets: `test-cli`, `integration-test-pkg`, `integration-test-cli`, `devcontainer`
- Improved CI workflow to test both `pkg/luks2` and `cmd/luks2` with merged coverage
- Updated `Dockerfile.integration` to run CLI and package integration tests separately
- Coverage threshold set to 90%

## [0.1.1-alpha] - 2025-12-17

### Added

- **FIPS-Compatible KDF Support**
  - Added KDF type constants (`KDFTypePBKDF2`, `KDFTypePBKDF2SHA256`, etc.)
  - Added `IsFIPSCompliantKDF()` function to check FIPS compliance
  - Added support for SHA-1, SHA-384 hash algorithms in PBKDF2
  - PBKDF2 with SHA-1/SHA-256/SHA-384/SHA-512 are FIPS-approved

- **SSD TRIM/DISCARD Support**
  - Added `Trim` option to `WipeOptions` for SSD optimization
  - Implemented `BLKDISCARD` ioctl for secure SSD erasure
  - TRIM is issued after data wipe for additional security on SSDs

- **Keyslot Hash Algorithm Selection**
  - Added `Hash` field to `AddKeyOptions` for PBKDF2 hash selection
  - Allows specifying hash algorithm when adding new keyslots

- **Comprehensive Test Coverage**
  - Added extensive unit tests for KDF functions
  - Added unit and integration tests for wipe operations
  - Improved test coverage for edge cases and error handling

### Changed

- Improved device size detection for block devices in wipe operations
- Added input validation for size parameters in wipe functions
- Added defense-in-depth buffer clearing in wipe operations
- Refactored hash function selection into reusable `getPBKDF2HashFunc()`

### Fixed

- Fixed potential issues with negative size values in wipe operations

## [0.1.0-alpha] - 2025-12-06

### Added

- **LUKS2 Volume Management**
  - Format new LUKS2 encrypted volumes
  - Unlock/lock volumes using device-mapper
  - Read and validate LUKS2 headers
  - Support for volume labels and UUIDs

- **Key Derivation Functions**
  - Argon2id (recommended, memory-hard)
  - Argon2i (side-channel resistant)
  - PBKDF2-SHA256/SHA512

- **Cryptography**
  - AES-256-XTS encryption
  - Anti-forensic information splitting (4000 stripes)
  - Secure random key generation
  - Constant-time key comparison

- **Filesystem Operations**
  - Create ext2, ext3, ext4 filesystems on unlocked volumes
  - Mount and unmount encrypted volumes
  - Loop device management for file-based volumes

- **Security Features**
  - Memory clearing of sensitive data
  - Input validation and path traversal protection
  - File locking for concurrent access protection
  - Passphrase length validation (8-512 bytes)

- **Secure Wipe**
  - Header-only wipe (fast)
  - Full device wipe with configurable passes
  - Individual keyslot wiping

- **CLI Tool (`luks2`)**
  - `create` - Create new encrypted volumes (block devices or files)
  - `open` - Unlock volumes
  - `close` - Lock volumes
  - `mount` - Mount unlocked volumes
  - `unmount` - Unmount volumes
  - `info` - Display volume information
  - `wipe` - Securely destroy volumes

- **Typed Error Handling**
  - Sentinel errors for common conditions
  - Typed errors (DeviceError, VolumeError, KeyslotError, CryptoError)
  - Full support for `errors.Is()` and `errors.As()`

- **Compatibility**
  - Full LUKS2 specification compliance
  - Interoperable with cryptsetup
  - Tested with cryptsetup 2.3+, Linux kernel 5.x+
