### Added

- **`DetectFilesystem` and type detection in `Mount`.** `DetectFilesystem(name)`
  reports the filesystem on an open mapping from `blkid -p` (never blkid's
  cache). `Mount` with an empty `FSType` mounts what it finds. Nothing found,
  more than one signature, or one that is not a filesystem is refused with
  `ErrFilesystemNotDetected`.
- **`ParseRecoveryKeyFormat`** turns a format name into a `RecoveryKeyFormat`,
  refusing anything but `dashed`, `hex` and `base64` (an empty name included)
  with `ErrInvalidRecoveryKeyFormat`.
- **`luks2 header restore --force`** passes `RestoreHeaderOptions.Force`
  through, so the CLI can restore over an intact primary that is not older. It
  still asks for `YES` unless `--batch-mode` is given, and warns that it rolls
  the volume back.

### Changed — BREAKING: `luks2 mount` mounts the detected filesystem, not ext4

- `luks2 mount` used to mount every volume as ext4, so the xfs and vfat volumes
  `create` makes could not be mounted with it. It now takes `--type`/`-t` and
  otherwise detects the type. A mapping with no recognizable filesystem is
  refused (exit 1) instead of being handed to `mount(2)` as ext4.

### Changed — BREAKING: `luks2 create` fails when it cannot open the new volume

- If `create` cannot attach a loop device to the new file volume or unlock it,
  it now prints the error on stderr, detaches a loop device it attached, keeps
  the container and **exits 1**. It used to print a warning and exit 0, so a
  script went on to mount a volume that was never opened.

### Changed — BREAKING: a header checksum algorithm other than sha256 is refused

- The binary header's `csum_alg` field was ignored and SHA-256 computed
  regardless, so a header claiming `sha1` over a SHA-256 checksum was read here
  and refused by cryptsetup. A header naming anything but `sha256` (the only
  algorithm cryptsetup writes) is now refused with
  `ErrUnsupportedHeaderChecksum`, which also matches `ErrInvalidHeader`.

### Security

- **Writers no longer reopen the device path after locking it.** `Wipe` and
  `WipeKeyslot` took their `O_EXCL` in-use claim on a second open of the path
  and never checked it was the locked device: a symlink re-pointed in between
  had `Wipe` overwrite a different disk, and `WipeKeyslot` claim an idle disk
  and then zero a keyslot on the in-use one. `ImportToken`, `RemoveToken` and
  `WriteHeader` read and wrote the header by reopening the path. The token
  and header writers now read and write through the locked descriptor; the
  wipes' `O_EXCL` claim is refused with the new `ErrDeviceChanged`, before
  anything is written, unless its device, inode and rdev match the locked
  descriptor, and `Wipe` then writes through that proven claim.
  `AddRecoveryKey` took the `VolumeUUID` it reports (and saves) from a second
  read of the path after enrolling; it now comes from the header read under
  the enrollment's lock. Format's same-file refusal now also returns
  `ErrDeviceChanged`.

### Fixed

- **`Unlock` reads the metadata under cryptsetup's read lock.** It takes
  `LOCK_SH` on the device and on `/run/cryptsetup/L_<maj>:<min>` before reading
  the header and holds them through the keyslot scan, releasing them before the
  device-mapper work. A cryptsetup command (or this library) writing the header
  is waited for, up to `DefaultLockWait`, instead of being read mid-rewrite;
  other readers are not delayed. Releasing cryptsetup's lock file now unlinks
  it only when no other holder remains, as cryptsetup does.
- **`luks2 recovery` refuses an unknown `--format` as a usage error**, before
  reading the passphrase. An empty `--format=` used to produce a dashed key.
- **Polling waits use the package clock.** The device-mapper readiness and
  busy-retry waits run on the injectable clock with a deadline.
- Stale comments and examples: the dashed recovery key is 74 characters, not
  71; `RecoveryKeyOptions.KDFType` describes the PBKDF2/1000 path that now
  exists; `create`'s usage examples use an absolute path.

### Tests

- Keyslot removal is held to `cryptsetup luksKillSlot`'s token update on the
  same header for every removal path (the keyslot is dropped from every token;
  a token left naming none is kept).
- The last `t.Skip` guards are gone: missing cryptsetup or VmLck fails the
  test, and the harness hostname is injected.
- The integration image installs `strace`, used to make real cryptsetup hold
  its write lock while `Unlock` reads.
- **`pkg/luks2` under `-race` is back inside its budget (#92):** 322 s to
  108 s on the same host. The FIPS-import child processes use the suite's
  calibrated-count seam and run in parallel, and the AF XOR, `clearBytes` and
  the ones-pattern fill no longer loop per byte (the coverage build counted
  every byte atomically).
