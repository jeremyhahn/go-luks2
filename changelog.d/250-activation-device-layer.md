### Security

- **`Unlock` maps only a key bound to the data segment (#250).** A passphrase
  that opened only an unbound keyslot had its key handed to dm-crypt, and the
  mapping returned garbage. Only keyslots bound to the segment are tried now,
  and the key must verify against that segment's digest. Otherwise the result is
  `ErrMasterKeyVerification`, which is also what cryptsetup does. `AddKey`
  checks the existing passphrase the same way.
- **A rolled-back `Unlock` no longer removes another caller's mapping (#250).**
  When two unlocks raced for one name, the loser's rollback matched the winner's
  dm UUID and removed the live mapping. The rollback now runs only after this
  call's own create succeeded, and is pinned to the device number that create
  returned.
- **Filesystem programs no longer run from `PATH` (#250).** mkfs, fsck, zpool,
  zfs and blkid run from fixed system directories with a two-variable
  environment, and every operand follows `--`. A program, or a symlink to
  one, is run only if the file and every directory above it are writable by
  nobody but root or the current user.

### Changed — BREAKING: activation refuses reencrypting and multi-segment containers

- **(#250)** A container with a mandatory requirement this library does not
  implement, such as `online-reencrypt-v2` from an interrupted
  `cryptsetup reencrypt`, is refused with `ErrUnsupportedRequirement`. It used to
  be mapped with one key over one segment. A header with more than one segment
  is refused with `ErrUnsupportedSegmentLayout`.

### Changed — BREAKING: mapping names are validated and nodes verified everywhere

- **(#250)** `MakeFilesystem`, `MakeFilesystemWithOptions`, `Mount`, `Lock`,
  `IsUnlocked` and `GetMappedDevicePath` reject an invalid mapping name with
  `ErrInvalidMappingName` (`IsUnlocked` returns false). `control` is no longer
  a valid name: `/dev/mapper/control` is device-mapper's control node. Before this,
  `MakeFilesystem("../sdb", ...)` ran mkfs on `/dev/sdb`. Device-mapper decides
  whether a mapping exists: `IsUnlocked` no longer answers true from a
  `/dev/mapper` node alone. `GetMappedDevicePath` returns a node only if its
  device number matches the mapping's, and returns `ErrDeviceNodeUnverified`
  otherwise. `Unlock` replaces a stale `/dev/mapper/<name>` instead of
  trusting it.

### Changed — BREAKING: `Unlock` requires a block device

- **(#250)** `Unlock` opens the device once, reads the header, the size and the
  keyslots through that descriptor, and gives dm-crypt its `major:minor`. A
  regular file is refused with `ErrNotBlockDevice`; attach it with
  `SetupLoopDevice` first. dm-crypt could never map a regular file anyway.

### Changed — BREAKING: ZFS names are validated, tools come from fixed directories

- **(#250)** ZFS pool, dataset, feature and property names that do not follow
  zpool's naming rules are refused with `ErrInvalidFilesystemOption`. A
  filesystem program that is only on `PATH`, or that sits in a directory
  writable by others, is refused with `ErrFilesystemTool`.

### Added

- **`IsMappingMounted(name)` (#250)** reports whether a filesystem on a mapping
  is mounted, by device number. `luks2 close` uses it. The old check asked
  whether `/dev/mapper/<name>` was a mount point, which it never is, so `close`
  never refused a mounted volume.

### Fixed

- **`Unlock` works under a mapping name of any valid length (#250).** The dm
  UUID is now cut to the 128 bytes the kernel stores before the create, as
  cryptsetup does. With a name over about 83 bytes the kernel used to cut it
  and every later identity check compared the uncut string.
- **`FindLoopDevice` matches by device and inode (#250)**, so a file named
  through a symlink or a bind mount finds its loop device. It now returns a
  `DeviceError` for a file that does not exist.
- **The keyring thread is discarded after an unlock (#250).** Resolving the
  session keyring can install one on the calling OS thread, and that thread used
  to return to the scheduler. The keyring work now runs on a locked thread that
  exits when it finishes.
- **Unlock errors name the real command (#250).** The remedy for a name in use
  or a mapping left live said `luks close <name>`; the CLI is `luks2`.
