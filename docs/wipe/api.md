# Wipe — API

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is an embedded Go
library; it has no REST, gRPC, QUIC, MCP or Unix-socket transport.

| Capability | Embedded (Go call) |
|---|---|
| Header-only crypto-erase | `(*luks2.Volume).Erase(ctx) error` |
| Full-device sanitize | `wipe.Sanitize(ctx, path, wipe.Params) error` |
| Zero one keyslot area | `(*luks2.Volume).RemoveKeyslot(ctx, slot) error` |

No request/response schema, status code mapping or `scp` permission applies.
See [volumes/api.md](../volumes/api.md) for the general Layer 0 statement
this folder inherits.
