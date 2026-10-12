# Loop devices — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-12 against base/331 (a9c840c)
> Conflicts with this document are defects. Fix them here first.

## Exported surface

`pkg/loop` is `//go:build linux` and root-only.

```go
func Attach(ctx context.Context, file string) (*Device, error)
func Find(ctx context.Context, file string) (*Device, error)
func Lookup(ctx context.Context, path string) (*Device, error)

type Device struct{ /* unexported */ }
func (d *Device) Path() string
func (d *Device) BackingFile() string
func (d *Device) Detach(ctx context.Context) (DetachState, error)

type DetachState int
const (
	Released DetachState = iota // the release was observed
	Deferred                    // accepted and postponed; a success
)

type Error = errs.Error

var (
	ErrNotFound         // "loop: no loop device found"
	ErrDetachIncomplete // "loop: detach did not become observable"
	ErrNodeAbsent       // "loop: allocated device's node did not appear under /dev"
	ErrDeviceReassigned // "loop: the device is now attached to a different file"
	ErrPermissionDenied // = internal/device's, shared with luks2
)
```

| Name | Contract |
|---|---|
| `Attach` | Attaches `file`, read-write and whole, to a free loop device and waits for its node to appear. The `Device` records the file's device and inode from the descriptor handed to `LOOP_SET_FD`. |
| `Find` | Returns the loop device whose backing file has the same device and inode as `file`, whatever path either was named by. With several, the first in `/sys/block` directory order. |
| `Lookup` | Returns a `Device` for a `/dev/loopN` node, attached or not. It records what the device is attached to now, or nothing; that is what `Detach` later holds it to. |
| `Device.Path` | The node, such as `/dev/loop0`, as `Attach` built it or the caller passed it. |
| `Device.BackingFile` | The absolute path of the backing file when the `Device` was obtained, or `""` for a `Device` from `Lookup` on an idle device. It is recorded once and not re-read. |
| `Device.Detach` | Detaches and waits until the release is observed; see below. |
| `Released`, `Deferred` | The two outcomes of a detach the kernel accepted. Both are success. |
| `Error` | The module's one error shape: `Kind` (the sentinel), `Op` and `Path` set at the exported entry, `Detail`, and the cause. |

## Invariants

- **Identity, not paths.** A `Device` holds the backing file's device and
  inode, or knows it held nothing. `Detach` reads the identity with
  `LOOP_GET_STATUS64` on the descriptor it then sends `LOOP_CLR_FD` on, and
  clears only when it matches. A device since attached to another file (or,
  from an idle `Lookup`, attached since) is refused with `ErrDeviceReassigned`;
  one with nothing attached any more is refused with an `ErrIO` error. Neither
  is touched. The check and the clear are two ioctls, so a reassignment between
  them remains possible.
- **No success without an authoritative observation.** `Detach` returns
  `Released` only after sysfs shows the association gone: the backing file
  changed from the one recorded before the clear, or, if that first reading
  failed, the device shows nothing attached. An unreadable state is retried and
  never concluded from. A device whose `/sys/block` entry is missing (a udev
  symlink, a partition) is unreadable, not unattached.
- **Our descriptor is closed before the wait**, because the release cannot
  complete while it is held. A failed close does not skip the wait; it is
  joined to whatever the wait concludes.
- **Deferred is decided at the bound, not on first sight.** Seeing the
  autoclear flag does not end the wait: a holder is usually momentary, and
  waiting turns most deferred cases into `Released`. Only a device still held
  with autoclear set when the bound expires returns `Deferred`, with the
  device still attached and released by the kernel when the last user goes.
- **`Find` never answers "not attached" when it could not tell.** If no device
  matches and any candidate's state or identity could not be read, it fails
  with an `ErrIO` error naming how many, not `ErrNotFound`.
- **`Attach` retries a lost race.** `LOOP_CTL_GET_FREE` names a number without
  reserving it; `EBUSY` from `LOOP_SET_FD` asks for another, up to 16 attempts,
  and the last `EBUSY` is returned if every one is taken.
- **Context.** Every entry checks `ctx` first, and both waits select on it.
  A canceled context returns an error matching `context.Canceled` or
  `context.DeadlineExceeded`. A `Detach` canceled after the clear has still
  sent `LOOP_CLR_FD`.
- **Concurrency.** A `Device` is immutable after construction and holds no
  lock. Two concurrent `Detach` calls on one `Device` are not coordinated: the
  second finds nothing attached, or the device reassigned.

Bounds, on the package's clock:

| Wait | Bound | Poll |
|---|---|---|
| Node to appear after `LOOP_CTL_GET_FREE` | 2 s | 500 µs |
| Release to be observed after `LOOP_CLR_FD` | 2 s | 500 µs |

## Error semantics

Match with `errors.Is` on the sentinel. Errors are `*loop.Error` with `Op`
(`Attach`, `Find`, `Lookup`, `Device.Detach`) and `Path` set, except that a
failure to list `/sys/block` in `Find`, or a `Lookup` whose read of the
device's `backing_file` fails for a reason other than "unattached", comes back
as the bare `os` error.

| Error | From | When |
|---|---|---|
| `ErrNotFound` | `Find` | No device is backed by the file, and every candidate was readable |
| `ErrNodeAbsent` | `Attach` | The kernel allocated a number and no `/dev/loopN` appeared within the bound. The allocation succeeded; this is not "no loop devices available". Check that devtmpfs or udev creates nodes in this mount namespace. |
| `ErrDetachIncomplete` | `Detach` | The clear was accepted and the release was not observed by the bound, with no autoclear flag seen. The detail says which: "something else still holds the device open" (a holder to find) or "the device's state was unreadable for N of M checks" (a host to fix), by whichever dominated the wait. |
| `ErrDeviceReassigned` | `Detach` | The device is backed by a different file than when the `Device` was obtained, or by a file where it had none. Nothing was done. |
| `ErrIO` (`luks2.ErrIO`) | all | Opening the file, `/dev/loop-control` or the node failed; `LOOP_CTL_GET_FREE`, `LOOP_SET_FD` or `LOOP_CLR_FD` failed; the backing identity could not be read; `Detach` found nothing attached; `Find` could not inspect a candidate |
| `ErrInvalidArgument` (`luks2.ErrInvalidArgument`) | `Lookup` | The path is not `/dev/loopN` |
| `context.Canceled`, `context.DeadlineExceeded` | all | The context ended |
| `ErrPermissionDenied` | none | Declared for the shared vocabulary. A refused open is an `ErrIO` error wrapping the `os` error (which matches `fs.ErrPermission`), not this sentinel. |

`ErrDetachIncomplete` is deliberately not "detach failed": the request
succeeded and something else has the device. `Deferred` is not an error at
all.

Across the CLI boundary every `pkg/loop` error has no row in
[the exit-status table](../volumes/cli.md#exit-status) and exits 1. In
`create`, a detach failure during cleanup is printed with the `losetup -d`
command to finish, and the exit status is the original failure's.

## Configuration

None. There are no options, environment variables or files. The bounds above
are fixed. Tests replace them, and every kernel call, through an unexported
per-package `sys` struct that `Attach`, `Find` and `Lookup` read once and hand
to the `Device`, so `Detach` uses the same seams as its constructor.

## Persistence

None. All state is the kernel's: `/sys/block/loopN/loop/backing_file` and
`autoclear`, and `LOOP_GET_STATUS64`. A missing `backing_file`, or a read that
fails with `ENODEV` or `ENXIO`, means attached to nothing (kernels differ);
any other failure means the state could not be read.

## Test strategy

- **Unit** (`pkg/loop`, no root): the release wait, the identity check, the
  node wait, sysfs state parsing and `Find`'s match and "could not tell" path,
  all against a `sys` literal, fake sysfs trees and a fake clock, so no test
  waits out a real bound (`detach_test.go`, `failure_test.go`,
  `find_test.go`, `loop_test.go`, `state_test.go`).
- **Integration** (`test/integration/loop`, root, real loop devices): attach,
  find (including through a symlink), detach, several devices at once,
  cleanup, and a deferred release against an immediate one. It runs in the
  devcontainer under `make coverage-combined`, which `make integration-test`
  reaches; the container needs `/dev/loop-control` and the loop
  device-cgroup rule ([volumes/engineering.md](../volumes/engineering.md)).
- **CLI.** The file-volume `create` flow, its cleanup detaches included, is
  unit-tested in `internal/cli` against a fake `looper`. The CLI integration
  suite drives `create` on a loop device the harness attached, not the
  file-volume path that attaches one itself.
- **Coverage.** `pkg/loop`'s ioctl paths need a real device, so it gates on the
  combined unit+integration tier, as the other root-only packages do.
- **Isolation.** Loop devices are not namespaced. The test harness records
  every device it attaches in a host-side ledger and detaches only those.

## Observability

No logging, metrics or audit records. A failure's `Error` carries `Op`
(`Device.Detach` and so on), `Path` and a `Detail` naming the device and the
reason; that text is the diagnostic.
