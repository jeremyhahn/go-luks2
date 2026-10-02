### Removed — BREAKING: ext2 and ext3 can no longer be created

- **`MakeFilesystem` and `MakeFilesystemWithOptions` refuse ext2 and ext3
  (#195).** They now return `ErrUnsupportedFilesystem` where they used to run
  `mkfs.ext2` / `mkfs.ext3`. ext2 has no journal, and this library does not
  offer either filesystem on an encrypted volume. The owner ruled on this in
  #195. Use ext4 instead. The `FilesystemExt2` and `FilesystemExt3` constants
  remain so that callers can name the types being refused, and their comments
  say why. The `luks2 create` CLI no longer offers them, and the README and
  `docs/cli` no longer list them.
- **`luks2 create` offers ext4, xfs and vfat.** Its help is derived from
  `SupportedFilesystems()` less zfs: the command calls `MakeFilesystem`, which
  cannot pass the pool name ZFS requires, so it does not advertise zfs.
- **`luks2 create` refuses any other filesystem before touching anything.**
  `create <file> <size> ext2` (or ext3, zfs, or an unknown type) now exits 1
  with "Unsupported filesystem" before the file is created, formatted,
  attached or unlocked. Previously a type the library refused was only
  discovered at the last step, leaving an unlocked, unformatted volume and
  exiting 0.

### Fixed

- **`SupportedFilesystems()` is now the single source of truth for the
  supported set (#195).** Before this, three places each gave a different
  answer. `SupportedFilesystems()` said ext4, xfs, zfs and vfat. The
  `MakeFilesystemWithOptions` switch added ext2 and ext3. The
  `CheckFilesystem` switch left out vfat. As a result,
  `IsFilesystemSupported` said no to ext2 and ext3 even though creating them
  worked, and `CheckFilesystem` refused vfat even though the library
  advertised and created it. Both functions now dispatch through one table,
  and a unit test run by `make ci` checks that table against the list in
  both directions. A type added to the list without a make and a check
  implementation fails that test. Types outside the set are refused with the
  new sentinel `ErrUnsupportedFilesystem` before any device is touched,
  as an `*UnsupportedFilesystemError` naming the refused type.
- **`MakeFilesystemWithOptions` and `CheckFilesystem` return typed errors.**
  A volume that is not unlocked is a `*DeviceError` wrapping
  `ErrVolumeNotUnlocked`; a failed checker is a `*FilesystemCommandError`
  carrying the command, device and output. Callers that matched the old
  message text should use `errors.Is` / `errors.As`.
- **`CheckFilesystem` supports vfat (#195).** It runs `fsck.fat -n` for a
  read-only check, or `fsck.fat -a` with `repair` set. `fsck.fat` comes from
  the same dosfstools package as the `mkfs.fat` that creates the filesystem.
  A repair that `fsck.fat` reports by exiting 1 is confirmed with a
  read-only `fsck.fat -n` recheck, and counts as success when the recheck
  is clean. `fsck.fat` exits 1 both after writing repairs and after stopping
  on an internal inconsistency, so the exit status alone cannot tell them
  apart.
- **`CheckFilesystem` documents that ZFS is not read-only.** For zfs the
  device argument is a pool name, and the call only starts `zpool scrub`
  without waiting for its result. On a pool with redundancy the scrub repairs
  damaged data whether or not `repair` is set. This behaviour is unchanged;
  it is now written down.
