# Header — API

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is an embedded Go
library; it has no REST, gRPC, QUIC, MCP or Unix-socket transport.

| Capability | Embedded (Go call) |
|---|---|
| Read the current header (the primary, or the secondary when the primary is damaged or older) | `(*Volume).Header(ctx) (*Header, error)` |
| Read the secondary header | `(*Volume).SecondaryHeader(ctx) (*Header, error)` |
| Rebuild the primary from the secondary | `(*Volume).RestorePrimaryHeader(ctx) error` |
| Rebuild the primary unconditionally | `(*Volume).ReplacePrimaryHeader(ctx) error` |
| Probe for LUKS2 | `luks2.Open`, then `(*Volume).Header(ctx)`: `ErrNotLUKS2` for a LUKS1 header, `ErrInvalidHeader` when neither copy is a valid LUKS2 header |

No request/response schema, status code mapping or `scp` permission applies.
See [volumes/api.md](../volumes/api.md) for the general Layer 0 statement
this folder inherits.
