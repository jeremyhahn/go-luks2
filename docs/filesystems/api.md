# Filesystems — API

> **Status: NORMATIVE** · Last verified: 2026-10-12 against 7ee49b8
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is an embedded Go
library; it has no REST, gRPC, QUIC, MCP or Unix-socket transport.

| Capability | Embedded Go call |
|---|---|
| List creatable types | `filesystem.Supported()` |
| Make | `filesystem.Make(ctx, device, t, MakeParams)` |
| Check | `filesystem.Check(ctx, device, t)` |
| Repair | `filesystem.Repair(ctx, device, t)` |
| Detect | `filesystem.Detect(ctx, device)` |
| Inspect | `filesystem.Inspect(ctx, device)` |
| Mount | `filesystem.Mount(ctx, MountParams)` |
| Unmount | `filesystem.Unmount(ctx, target, UnmountFlags)` |
| Is a path a mount point | `filesystem.IsMounted(ctx, target)` |
| Is a device mounted | `filesystem.DeviceMounted(ctx, major, minor)` |

The other exported identifiers of `pkg/filesystem`:

| Kind | Identifiers |
|---|---|
| Types and constants | `Type`, `Ext4`, `XFS`, `ZFS`, `FAT32`; `UnmountFlags`, `Force`, `Detach`, `Expire` |
| Parameter and result structs | `MakeParams`, `Ext4Params`, `XFSParams`, `ZFSParams`, `MountParams`, `CheckResult`, `Info` |
| Errors | `ErrInvalidArgument`, `ErrUnsupported`, `ErrNotDetected`, `ErrTool`, `ErrNotMounted`, `Error`, `*CommandError` (`(*CommandError).Error()`, `(*CommandError).Unwrap()`) |

Signatures, fields and error meanings:
[engineering.md](engineering.md#exported-surface). There is no request schema,
status-code mapping or `scp` permission: the library has no process boundary.
A consumer that re-exposes these over a transport documents that mapping in its
own repository.
