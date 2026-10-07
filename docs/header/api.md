# Header — API

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is a Layer 0 library (docs/00
§L1 exemption); REST/gRPC/QUIC/MCP/Unix: not applicable.

| Capability | Embedded (Go call) |
|---|---|
| Read the primary header | `(*Volume).Header(ctx) (*Header, error)` |
| Read the secondary header | `(*Volume).SecondaryHeader(ctx) (*Header, error)` |
| Rebuild the primary from the secondary | `(*Volume).RestorePrimaryHeader(ctx) error` |
| Rebuild the primary unconditionally | `(*Volume).ReplacePrimaryHeader(ctx) error` |
| Probe for LUKS2 | `luks2.Open`, then `(*Volume).Header(ctx)`: `ErrNotLUKS2` when the device is not LUKS2 |

No request/response schema, status code mapping or `scp` permission applies.
See [volumes/api.md](../volumes/api.md) for the general Layer 0 statement
this folder inherits.
