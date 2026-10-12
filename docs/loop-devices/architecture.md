# Loop devices — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (3da0ff2)
> Conflicts with this document are defects. Fix them here first.

Turning a regular file into a block device and back. dm-crypt activates a
mapping on a block device only, so a LUKS2 container held in an image file
needs a loop device in front of it before it can be opened. This feature is
the attach, find and detach of that device; activating a mapping on it is
[dm-crypt activation](../dm-crypt-activation/)'s contract, and making a
filesystem on the mapping is [filesystems](../filesystems/)'s.

## The problem and the shape chosen

Two kernel facts shape the package.

- **Loop devices are host-global and reused.** A number freed by one process
  can be claimed by another between any two calls, and the same file can be
  reached through many paths (a symlink, a bind mount, another mount
  namespace). Neither a `/dev/loopN` path nor a backing-file path string is an
  identity. A `Device` therefore records the backing file's device and inode
  when it is obtained, `Find` matches on device and inode, and `Detach`
  refuses a device that is no longer backed by that file.
- **Releases are asynchronous.** `LOOP_CLR_FD` can return before the
  association is gone: while any descriptor for the device is still open the
  kernel marks it autoclear and defers the release. So `Detach` waits until
  the release is observed, and reports a release still held at the bound as
  `Deferred`, a success, the way `losetup -d` does on a busy device.

The package is `pkg/loop`, a public package of its own (DESIGN.md §A.4,
§B.5): it is LUKS-independent, consumed directly by go-trusted-platform, and
has its own trust boundary (root-only loop ioctls). Callers import only what
they use.

```go
// pkg/loop
func Attach(ctx context.Context, file string) (*Device, error)
func Find(ctx context.Context, file string) (*Device, error)   // by backing file; ErrNotFound
func Lookup(ctx context.Context, path string) (*Device, error) // by /dev/loopN
type Device struct{ /* unexported */ }
func (d *Device) Path() string
func (d *Device) BackingFile() string
func (d *Device) Detach(ctx context.Context) (DetachState, error)
type DetachState int
const (Released DetachState = iota; Deferred) // Deferred is success
```

### Alternatives rejected

| Alternative | Why not |
|---|---|
| Exec `losetup` | The ioctls give the backing file's device and inode on the very descriptor that is attached or cleared. `losetup`'s output gives a path, which is not an identity, and adds a binary to the trust boundary. |
| Detach by path (a bare `DetachLoopDevice(path)`) | A path names whatever the number holds at that moment. A `Device` carries the identity recorded when it was obtained, and `Lookup` exists so a caller holding only a path still detaches through one. |
| Match `Find` on the path sysfs prints | The printed path differs from the argument for the same file through a symlink, a bind mount or another mount namespace. Device and inode do not. |
| Return as soon as `LOOP_CLR_FD` succeeds | A caller that asks `Find` right after could be told the file is still attached, intermittently. |
| Fail a detach the kernel deferred | It is what `losetup -d` reports success for. Failing it breaks callers detaching a device that is legitimately still in use. |
| A `loop.Option` on `Attach` (read-only and so on) | Nothing attaches any other way yet. It is added with the first caller that needs it. |
| Building on darwin | The loop ioctls do not exist there. The package is `//go:build linux`; only `pkg/luks2` and `pkg/keyprovider` are cross-platform. |

## Component boundaries

| Piece | Holds |
|---|---|
| `pkg/loop` | Attach (`LOOP_CTL_GET_FREE`, `LOOP_SET_FD`), find (sysfs scan, `LOOP_GET_STATUS64`), lookup, detach (`LOOP_CLR_FD`) and the release wait |
| `internal/device`, `internal/errs`, `internal/clock` | The shared `ErrPermissionDenied`, the module's one error shape, and the clock the waits are measured on |
| `internal/cli` | The `looper` boundary: `create`'s file-volume flow is its only caller |
| `pkg/luks2` | Nothing here. Its depguard rule denies `pkg/loop`; a `Volume` opened on a loop device's path neither knows nor cares that it is one |

The CLI reaches `pkg/loop` through a small unexported interface, so its unit
tests run without root. `realLooper` is the production implementation and
calls `pkg/loop` unmodified.

## Data flow

**Attach.** Open the file read-write and record its device and inode from that
descriptor. Ask `/dev/loop-control` for a free number, wait for its node to
appear under `/dev`, open it and hand it the file with `LOOP_SET_FD`. The
number is named, not reserved, so a concurrent caller can take it first; an
`EBUSY` from `LOOP_SET_FD` asks for another number, up to 16 times.

The number is not the node. Creating `/dev/loopN` belongs to devtmpfs or
udev, and neither need have finished, or be running. The pre-created range
(typically `loop0` to `loop7`) hides this, which is why a missing node shows
up as "works for the first N, fails past them". `Attach` waits for the node
and reports `ErrNodeAbsent` if it never appears.

**Find.** Stat the file for its device and inode, scan `/sys/block/loop*`,
and for each bound device read the backing identity with
`LOOP_GET_STATUS64`. A device whose state cannot be read is counted, not
skipped as a non-match: if no match is found and any candidate was
unreadable, `Find` fails rather than answering `ErrNotFound`. "Not attached"
and "could not tell" are different answers, and a caller about to attach
because it was told "not attached" would create a second writer of one LUKS
container.

**Lookup.** Accept only `/dev/loopN`, read its state from sysfs, and record
whatever it is attached to now, or nothing.

**Detach.** Record the device's state, open it, check on that descriptor that
it is still backed by the recorded file, send `LOOP_CLR_FD`, close the
descriptor (the release cannot complete while it is held), and poll sysfs
until the release is observed or the bound expires.

**The file-volume `create`.** Format the regular file in place, attach a
loop device, re-open the volume on the device's path, unlock it, activate
`luks-auto` on it ([dm-crypt activation](../dm-crypt-activation/), which hands
the key over through the [kernel keyring](../kernel-keyring/)), then make the
filesystem ([filesystems](../filesystems/)). On success the device stays
attached for the open volume. On a failure after the attach, the device
`Attach` returned is detached again.

`open` does not attach. Given an image file it refuses with "not a block
device"; the operator attaches one first (`losetup -f --show <file>`) and
opens the loop device.

Nothing is persisted. The only state is the kernel's, read back from
`/sys/block/loopN/loop/` and the loop ioctls each time.

## Trust boundaries

Root only: `LOOP_CTL_GET_FREE`, `LOOP_SET_FD` and `LOOP_CLR_FD` need
`CAP_SYS_ADMIN`, and the `/dev` nodes are generally unreadable to an
unprivileged caller. No key material crosses this package: a loop device
carries ciphertext, and the volume key goes from the protected key buffer to
dm-crypt through the kernel keyring without passing here.

The loop namespace is global to the host. `Detach` reads the identity on the
descriptor it then clears, but the check and the clear are two ioctls, so a
reassignment between them remains possible.

## What this feature deliberately does not do

- No read-only, offset, size-limit, direct-I/O or autoclear attach. `Attach`
  attaches the whole file, read-write.
- No automatic detach on `close`. `luks2 close` removes the mapping and leaves
  the loop device; `losetup -d` detaches it.
- No partitions on loop devices (`/dev/loopNpM` is not a loop node to
  `Lookup`).
- No attempt to make a missing device node (no `mknod`): that is devtmpfs's
  or udev's job, and `ErrNodeAbsent` says it did not happen.
