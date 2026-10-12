# Filesystems — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (f871541)
> Conflicts with this document are defects. Fix them here first.

Package `github.com/jeremyhahn/go-luks2/pkg/filesystem`. Linux only. Every name
below is checked against `go doc -all ./pkg/filesystem`.

## Exported surface

### Functions

| Function | Behaviour |
|---|---|
| `Supported() []Type` | The types `Make` and `Check` accept. Returns a copy. |
| `Make(ctx, device string, t Type, p MakeParams) error` | Creates a filesystem of type `t` on a device path. |
| `Check(ctx, device string, t Type) (CheckResult, error)` | Checks without writing (ZFS: starts a scrub). |
| `Repair(ctx, device string, t Type) (CheckResult, error)` | `Check` with repair enabled for ext4, xfs and vfat. |
| `Detect(ctx, device string) (Type, error)` | The filesystem `blkid -p` identifies on the device. |
| `Inspect(ctx, device string) (*Info, error)` | Label, UUID, type and block size from `blkid`'s cache. |
| `Mount(ctx, p MountParams) error` | `mount(2)`. |
| `Unmount(ctx, target string, flags UnmountFlags) error` | `umount2(2)`. |
| `IsMounted(ctx, target string) (bool, error)` | Whether `target` is a mount point, from `/proc/mounts`. |
| `DeviceMounted(ctx, major, minor uint32) (bool, error)` | Whether a filesystem on that device number is mounted, from `/proc/self/mountinfo`, in this process's mount namespace. |

### Types and constants

| Name | Definition |
|---|---|
| `Type` | `string`, spelled as `blkid` and the tools spell it (`vfat`, not `fat32`) |
| `Ext4`, `XFS`, `ZFS`, `FAT32` | `"ext4"`, `"xfs"`, `"zfs"`, `"vfat"`. `Supported()` returns these four. |
| `MakeParams` | `Label string`, `BlockSize int` (ext4/xfs, 0 = default), `Force bool`, `Ext4 *Ext4Params`, `XFS *XFSParams`, `ZFS *ZFSParams`. The zero value means library policy. |
| `Ext4Params` | `JournalSize`, `InodeSize`, `InodesPerGroup int`; `ReservedBlocksPercent float64`; `StrideSize`, `StripeWidth int`; `DisableMetadataChecksums`, `EnableLargeDir`, `Enable64bit bool` |
| `XFSParams` | `AgCount`, `BlockSize`, `InodeSize`, `SectorSize`, `LogSize int`; `RealTime`, `RefLink`, `BigTime`, `NoAlign bool` |
| `ZFSParams` | `PoolName`, `DatasetName`, `Compression`, `RecordSize`, `MountPoint string`; `Ashift int`; `EnableDedup bool`; `Features []string`; `Properties map[string]string` |
| `CheckResult` | `Repaired bool`, `RebootRequired bool` |
| `Info` | `Type Type`, `Label`, `UUID string`, `BlockSize int`, `TotalSize`, `UsedSize`, `FreeSize uint64`, `MountPoint string` |
| `MountParams` | `Source`, `Target string`, `Type Type` (empty = detect), `Flags uintptr` (`mount(2)` flags), `Data string` |
| `UnmountFlags` | `int`. `Force`, `Detach`, `Expire`; zero is an ordinary unmount. |
| `Error` | Alias of the internal error shape: a classifying `Kind`, a `Detail` string and a wrapped `Err`. |
| `CommandError` | `Command string`, `ExitCode int`, `Output string`, `Err error`; has `Error()` and `Unwrap()`. |

`Info.TotalSize`, `UsedSize`, `FreeSize` and `MountPoint` are reserved: `Inspect`
does not fill them.

### Tools

| Operation | Program | Arguments |
|---|---|---|
| `Make` ext4 | `mkfs.ext4` | `-L`, `-b`, `-F`, `-J size=`, `-I`, `-m`, `-E stride=,stripe_width=`, `-O 64bit,dir_index,large_dir,^metadata_csum`, then `-- device` |
| `Make` xfs | `mkfs.xfs` | `-L`, `-f`, `-b size=`, `-s size=`, `-i size=`, `-d agcount=`, `-l size=…m`, `-m reflink=,bigtime=`, `-d noalign`, then `-- device` |
| `Make` vfat | `mkfs.fat` | `-F 32`, `-n label`, then `-- device` |
| `Make` zfs | `zpool create`, then `zfs create` for a named non-`root` dataset | `-f`, `-m`, `-o ashift=`, pool properties, `-O` dataset properties, `-o feature@<name>=enabled`, then `-- pool device` |
| `Check` / `Repair` ext4 | `e2fsck` | `-n` / `-p` |
| `Check` / `Repair` xfs | `xfs_repair` | `-n` / none |
| `Check` / `Repair` vfat | `fsck.fat` | `-n` / `-a` |
| `Check` / `Repair` zfs | `zpool scrub` | `-- pool` |
| `Detect` | `blkid` | `-p -o export -- device` |
| `Inspect` | `blkid` | `-o export -- device` |

`Make` for ZFS requires `MakeParams.ZFS` with a `PoolName`. `DatasetName` empty or
`root` creates the pool only.

## Invariants

- Every function returns `ctx.Err()` as its error kind, without running
  anything, when `ctx` is already done.
- Every function takes a device path. A device-mapper mapping name is the
  caller's to resolve and verify first. ZFS `Check`/`Repair` take a pool name.
- An unsupported type is refused with `ErrUnsupported` before a device is
  touched. That includes the empty type.
- Tools are resolved from a fixed set of system directories, never `PATH`, and
  run with `PATH` limited to those directories and `LC_ALL=C`; operands follow
  `--` ([architecture.md](architecture.md#trust-boundary-external-programs)).
- `Detect` never uses `blkid`'s cache; `Inspect` does, and can be stale after
  a `Make`.
- `Mount` refuses a target that does not exist (`ErrInvalidArgument`). It has no
  already-mounted refusal: stacking is legal, and `IsMounted` answers the
  question.
- `Unmount` validates flags before the syscall: a value outside `Force`,
  `Detach`, `Expire`, or `Expire` combined with `Force` or `Detach`, is
  `ErrInvalidArgument`. The kernel decides whether the path is a mount point;
  an `EINVAL` then means `ErrNotMounted`.
- `Check` never writes for ext4, xfs and vfat. A ZFS `Check` starts a scrub,
  which repairs damaged data on a redundant pool, and returns once it has
  started.
- `Repair` for ext4 treats `e2fsck` exit 1 (corrected) and 2 (corrected, reboot
  requested) as success; a status with an uncorrected or failure bit is an
  error. A vfat repair that `fsck.fat` reports by exiting 1 is confirmed with a
  read-only recheck. `xfs_repair` and `zpool scrub` report neither, so their
  `CheckResult` is always zero. ZFS ignores repair.
- `DeviceMounted` matches the device number, so a filesystem mounted through
  an alias path is still seen.
- Nothing here holds state across calls.

## Error semantics

| Error | Returned when |
|---|---|
| `ErrInvalidArgument` | A ZFS pool, dataset, feature or property name could be read as an option or breaks the tool's naming rules; `ZFSParams` missing or `PoolName` empty on a ZFS `Make`; a bad `UnmountFlags`; a `Mount` target that does not exist. |
| `ErrUnsupported` | `Make`, `Check` or `Repair` is given a type outside `Supported()`, including `ext2`, `ext3` and the empty string. |
| `ErrNotDetected` | `Detect`, or `Mount` with no type, found no signature, more than one, or one that is not a filesystem. The message names what was found. |
| `ErrTool` | A program is not in the fixed directories, or it or a directory above it is owned by another user or writable by group or others. |
| `ErrNotMounted` | `Unmount`'s target is not a mount point. |
| `*CommandError` | A creator, checker or `blkid` ran and exited unsuccessfully, or could not be started. `ExitCode` is -1 when it did not start or did not exit normally. `Output` is its combined stdout and stderr. `Command` is the program, or `zpool create` / `zfs create` for ZFS `Make`. `Unwrap` reaches the run error, so a program that was not found also matches `ErrTool`. |
| `Error` with an I/O kind | A failed `mount(2)` or `umount2(2)` other than `EINVAL`, or an unreadable mount table. |

`Inspect` reports a `blkid` failure as an `Error` whose detail is `blkid failed`;
its kind is `ErrTool` when the program was unavailable. Match with
`errors.Is` for the sentinels and `errors.As` for `*CommandError`.

When a tool is absent: `Make`, `Check`, `Repair` and `Detect` return a
`*CommandError` (`ExitCode` -1) that matches `ErrTool`; `Inspect` returns an
`Error` that matches `ErrTool`; `Mount` with an explicit type needs no tool and
still works; `Mount` with no type needs `blkid`. Nothing falls back to another
location or another tool.

## Configuration

None. No environment variables, files or options; behaviour is set by the
arguments. The tool directory list and the tool environment are fixed in the
package.

## Persistence

None. The package writes only what the tools and the kernel write to the device
and the mount table.

## Test strategy

- Unit tests substitute the tool runner and the syscalls behind unexported
  seams, and use fake programs on a controlled directory, so they need neither
  root nor a real device. The mount-table parsers are driven from tables the
  test writes, including escaped paths.
- Integration tests under `test/integration/filesystem/` run the package against
  real devices and the real tools, as root.
- The per-package coverage floor is in `coverage-floors.txt`.

## Observability

None. The package does not log; a `*CommandError` carries the tool's output for
the caller to log.
