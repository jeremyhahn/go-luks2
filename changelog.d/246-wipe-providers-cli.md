### Changed — BREAKING: `luks2 create` on a block device asks for `YES` and refuses existing data

- **Formatting a block device needs confirmation (#246).** `create /dev/X` asks
  for `YES`. `--batch-mode` (or `--yes`) skips the question for scripts. Before
  this, it formatted the device without asking. It now refuses a device that
  already holds a LUKS header (either copy) or a filesystem, RAID, LVM or
  partition-table signature unless `--force` is given. It always refuses a
  device the kernel reports in use. Scripts that create volumes on block
  devices must add `--batch-mode`.

### Changed — BREAKING: an unconfirmed `wipe` or `header restore` exits 1

- **A canceled destructive command now fails (#246).** Any answer other than
  `YES`, end of input, or a read error used to print "canceled" and exit 0, so
  a script read a wipe that never happened as done. These now exit 1.
  `--batch-mode` (or `--yes`) skips the question.

### Changed — BREAKING: a header-only wipe also erases the keyslots area

- **`Wipe` with `HeaderOnly` is now a crypto-erase (#246).** It used to zero
  only the two header copies, plus the 4 KiB binary header of any stray copy.
  The keyslot material stayed on the device, and so did a stray copy's JSON,
  salts included. Anyone holding a pre-wipe copy of the header could put it
  back and open the volume with the old passphrase. The wipe now zeroes the
  whole keyslots area, every declared keyslot area, and every other
  recognizable header copy's JSON. It stops at the start of the data segment.

### Changed — BREAKING: key-provider helpers need absolute paths, a clean environment and a FIDO2 device

- **Helpers are never looked up on PATH (#246).** A `CommandKeyProvider` or
  `ExecConfig` helper path that is not absolute is refused with
  `ErrHelperPathNotAbsolute`. The docs already said PATH was not searched, but
  `exec` searched it for any bare name. Helpers no longer inherit the
  process environment. They get a system `PATH` plus the new
  `CommandKeyProvider.Env`.
- **`ExecConfig.Device` is required (#246).** An empty device used to reach
  the helper as an empty argument. It is now refused with `ErrNoFIDO2Device`,
  and the device is passed after `--`.

### Changed — BREAKING: the device lock also takes cryptsetup's lock

- **go-luks2 and cryptsetup now exclude each other (#246).** For a block
  device, `AcquireFileLock` (used by every header write) now also takes
  cryptsetup's own lock, `flock` on `/run/cryptsetup/L_<major>:<minor>`, the
  way cryptsetup does. Before, cryptsetup could change a header this package
  held locked. A process that cannot create or open that file (normally
  anything but root) can no longer lock a block device. Image files are
  unchanged: cryptsetup locks the file itself, which this package already did.

### Fixed

- **`--no-verify` turns off a standard's verification (#246).** It only hid
  the "Verify" line and the DoD standards still verified. The new
  `WipeOptions.NoVerify` is what it sets.
- **Wipe verification reads the medium (#246).** It reads back with
  `O_DIRECT`, including a loop device's backing file. The random pass is now
  AES-256-CTR under a per-pass key, so the DoD sequences, which end with a
  random pass, are actually verified. Before, verification read the page cache
  and skipped random passes.
- **`Wipe` and `WipeKeyslot` refuse a device in use (#246).** They open block
  devices with `O_EXCL` and return `ErrDeviceInUse` for a mounted, mapped or
  held device.
- **Concurrent enrollments no longer overwrite each other's token (#246).**
  `EnrollKeyProvider` and `AddRecoveryKey` hold one device lock from choosing
  the token slot to writing the token.
- **FIDO2 tokens keep their PIN and user-verification requirements (#246).**
  They are written as `fido2-clientPin-required` and `fido2-uv-required` and
  read back by `ProviderFromToken`.
- **A helper's output read ends with `ctx` (#246).** It also ends if the
  helper exits while a process it started still holds the pipe.
- **`create <file>` creates the file safely (#246).** It uses `O_EXCL` and
  `O_NOFOLLOW` at mode 0600, instead of a stat-then-create that raced, followed
  symlinks, and made the file 0644. Cleanup removes only the file this run
  made.
- **Relative paths work in every command (#246).** The documentation shows
  them, and the CLI now resolves them.
- **Strict size and `--passes` parsing (#246).** `10x`, `1.5G` and overflowing
  values are refused instead of silently truncated.
- **An empty `--key-file ""` is refused (#246).** It no longer falls back to
  the prompt or to standard input.
- **Passphrase buffers are wiped on every path (#246).** This covers a failed
  confirmation read and a piped line whose buffer grew.
- **`recovery add` rolls back a key it could not show (#246).** If the key
  cannot be displayed, the CLI removes its keyslot and token. If that fails, it
  names the slot to remove.
- **The integration suite runs when its state directory belongs to the
  invoking user (#246).** The launcher mounts a root-owned `root-ledger`
  subdirectory in that case instead of the directory itself, which the root
  reaper must not trust. Before, every run refused until the directory was
  removed by hand.
