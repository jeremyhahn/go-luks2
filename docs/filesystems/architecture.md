# Filesystems — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (f871541)
> Conflicts with this document are defects. Fix them here first.

`pkg/filesystem` makes, checks, repairs, detects and inspects filesystems on a
block device, and mounts and unmounts them. It is independent of LUKS2: it
knows nothing about headers, keys or mappings, and `pkg/luks2` does not import
it. A consumer imports it on its own, or together with `pkg/dmcrypt` and
`pkg/loop` to put a filesystem on an opened volume
([volumes](../volumes/architecture.md)).

## Shape

Two mechanisms, split by what the work needs:

| Work | Mechanism |
|---|---|
| `Make`, `Check`, `Repair` | External tool: `mkfs.ext4`, `mkfs.xfs`, `mkfs.fat`, `zpool`, `zfs`, `e2fsck`, `xfs_repair`, `fsck.fat` |
| `Detect`, `Inspect` | External tool: `blkid` |
| `Mount`, `Unmount` | `mount(2)` and `umount2(2)` syscalls (root) |
| `IsMounted`, `DeviceMounted` | Reads `/proc/mounts` and `/proc/self/mountinfo` |

Every function takes a device PATH, never a device-mapper mapping name.
Turning a mapping name into a path, and checking that the path really names
that mapping, is the caller's job; `pkg/luks2` and the CLI do it with
device-mapper before they call here. The one exception to "device path" is
ZFS `Check`/`Repair`, which take a pool name.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Link libblkid, libext2fs and friends | cgo, and a second implementation of each tool's behaviour to keep in step with the distribution's |
| Write each filesystem's `mkfs` and `fsck` in Go | The tools are what an operator expects to have run; their output and exit codes are the contract |
| Resolve tools through the caller's `PATH` | A hostile `PATH` or a writable directory on it would run attacker code as root; see below |
| Refuse `Mount` over an existing mount point | Linux permits stacking, so "already mounted" is a legal state; a caller that cares asks `IsMounted` |
| Pre-check `Unmount` against `/proc/mounts` | The kernel already decides, and `/proc/mounts` escapes spaces (`\040`), so a string compare would refuse a real mount point |
| Support ext2 and ext3 | Unsupported by design; `Detect` still reports them as the raw strings `ext2` and `ext3`, because that is what `blkid` found |

## Trust boundary: external programs

The package runs programs as root on a device that may hold untrusted data, so
it narrows what can be run and how:

- A program is found only in `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`,
  `/usr/local/sbin` and `/usr/local/bin`, never through `PATH`.
- It must be owned by root or the calling user and writable by nobody else, and
  every directory leading to it must meet the same rule (a sticky directory is
  allowed). A program that fails is refused with `ErrTool`, as is one that is
  not found in any of those directories.
- It runs with `PATH` set to those same directories and `LC_ALL=C`, and nothing
  else from the caller's environment.
- Every operand follows `--`, so a device path or name that starts with `-` is
  not read as an option. ZFS pool, dataset, feature and property names are also
  validated first and refused with `ErrInvalidArgument` if they could be read as
  an option or break the tool's naming rules.

`Detect` reads the device itself with `blkid -p` and never `blkid`'s cache,
which can describe a device as it was before the last `Make`. `Detect` refuses
rather than guesses: nothing found, more than one signature, or a signature
that is not a filesystem (a LUKS container, swap, a RAID or LVM member) is
`ErrNotDetected`. `Mount` with no type uses `Detect`, so it inherits that.

## Data flow

```
caller ──► Make/Check/Repair/Detect/Inspect ──► internal/command ──► tool (blkid, mkfs.*, ...)
caller ──► Mount/Unmount ───────────────────► mount(2) / umount2(2)
caller ──► IsMounted/DeviceMounted ─────────► /proc/mounts, /proc/self/mountinfo
```

Nothing is persisted by the package. Every function checks `ctx` first and
returns before touching a device or starting a tool when it is already done.

## What it deliberately does not do

- Resolve or verify device-mapper mapping names.
- Wait for or report a ZFS scrub (`Check` starts it and returns).
- Populate `Info.TotalSize`, `UsedSize`, `FreeSize` or `MountPoint`; they are
  reserved for a future probe.
- Pick a default filesystem for a caller; a caller that omits the type to
  `Mount` gets detection, and one that omits it elsewhere gets
  `ErrUnsupported`.
- Provide a CLI for `Check`, `Repair` or `Inspect` ([cli.md](cli.md)).
