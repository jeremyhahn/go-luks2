# Loop devices — API

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (3da0ff2)
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is an embedded Go
library; it has no REST, gRPC, QUIC, MCP or Unix-socket transport.

| Capability | Embedded (Go call) |
|---|---|
| Attach a file | `loop.Attach(ctx, file) (*loop.Device, error)` |
| Find the device backing a file | `loop.Find(ctx, file) (*loop.Device, error)` |
| Get a handle for `/dev/loopN` | `loop.Lookup(ctx, path) (*loop.Device, error)` |
| Device node | `(*loop.Device).Path() string` |
| Backing file | `(*loop.Device).BackingFile() string` |
| Detach and wait | `(*loop.Device).Detach(ctx) (loop.DetachState, error)` |

No request/response schema, status code mapping or `scp` permission applies.
Errors and their meaning are in [engineering.md](engineering.md#error-semantics).
See [volumes/api.md](../volumes/api.md) for the general Layer 0 statement this
folder inherits.
