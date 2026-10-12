# Filesystems — API

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (f871541)
> Conflicts with this document are defects. Fix them here first.

A Layer 0 library: the embedded Go call is the only transport, and no REST,
gRPC, QUIC, MCP or Unix-socket form exists
([volumes/api.md](../volumes/api.md) states the exemption).

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

Signatures, parameter structs, constants and errors:
[engineering.md](engineering.md#exported-surface). There is no request schema,
status-code mapping or `scp` permission: the library has no process boundary.
A consumer that re-exposes these over a transport documents that mapping in its
own repository.
