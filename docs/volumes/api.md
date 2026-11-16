# Volumes — API

> **Status: NORMATIVE** · Last verified: 2026-10-12 against 7ee49b8
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is an embedded Go
library; it has no REST, gRPC, QUIC, MCP or Unix-socket transport.

| Transport | Form |
|---|---|
| Embedded (Go call) | `pkg/luks2` directly; see [engineering.md](engineering.md#exported-surface) for the volume-lifecycle surface |
| Unix socket | None |
| REST | None |
| gRPC | None |
| QUIC | None |
| MCP | None |

There is no request/response schema, status code mapping or `scp` permission
to document here: this library has no process boundary of its own. A consumer
that re-exposes volume operations over one of those transports (for example
go-trusted-platform's `services/luks` re-export frontage) documents that
mapping in its own repository, not here.

## Volume lifecycle identifiers

Signatures are in [engineering.md](engineering.md#exported-surface) and
`go doc`; this table names what each call is for.

| Capability | Embedded (Go call) |
|---|---|
| Open a container | `Open(ctx, path, ...Option) (*Volume, error)`; options `WithReadOnly()` and `WithLockWait(d)` (default `DefaultLockWait`) |
| The handle | `Volume`, `(*Volume).Path()`, `(*Volume).Close()` (idempotent) |
| Create a container | `(*Volume).Format(ctx, pass, FormatParams)`; `FormatParams.Validate`; zero fields mean `DefaultCipher`, `DefaultKeySize`, `DefaultHash`, `DefaultSectorSize` and `DefaultKDFType()` |
| Unlock | `(*Volume).Unlock`, `(*Volume).UnlockKeyslot`, `(*Volume).UnlockWithProvider`, `(*Volume).UnlockWithVolumeKey`, each returning a `*Key` (`Key.Keyslot`, `Key.Size`, `Key.Destroy`) |
| Geometry for activation | `(*Volume).Target(ctx, key) (*Target, error)`; `Segment` (a `Size` of `SizeDynamic` runs to the end of the device) |
| Crypto-erase | `(*Volume).Erase(ctx)` |
| Passphrase policy | `ValidatePassphrase(pass)`, `MinPassphraseLength`, `MaxPassphraseLength` |

| Error | Returned when |
|---|---|
| `Error` | The one error struct (`Op`, `Path`, `Kind`, `Detail`, `Err`); `Kind` is a sentinel below or `ctx.Err()` |
| `ErrClosed`, `ErrReadOnly` | The handle was closed, or opened `WithReadOnly` and asked to write |
| `ErrNotLUKS2`, `ErrInvalidHeader`, `ErrUnsupported`, `ErrUnsupportedRequirement` | The device holds no LUKS2 header, a malformed one, or one this library does not implement |
| `ErrInvalidArgument`, `ErrInvalidCredential`, `ErrIO`, `ErrNoSpace` | Module-wide kinds: a bad operand, a credential outside the policy, an I/O failure, no room in the header |
| `ErrDeviceNotFound`, `ErrPermissionDenied`, `ErrDeviceInUse`, `ErrDeviceChanged`, `ErrDeviceCacheStale` | The device layer's refusals |
| `ErrLockContended`, `ErrMetadataLockUnavailable`, `LockTimeoutError` | A lock could not be taken within `WithLockWait` |
| `ErrProtectedMemory`, `ErrNotLockedMemory`, `NotLockedMemoryError` | Key custody: no locked memory, or a caller's handle that is not locked memory |

A command-line process is not a transport in this sense; `cmd/luks2` is
documented in [cli.md](cli.md).
