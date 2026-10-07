# Wipe — API

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is a Layer 0 library (docs/00
§L1 exemption); REST/gRPC/QUIC/MCP/Unix: not applicable.

| Capability | Embedded (Go call) |
|---|---|
| Header-only crypto-erase | `(*luks2.Volume).Erase(ctx) error` |
| Full-device sanitize | `wipe.Sanitize(ctx, path, wipe.Params) error` |
| Zero one keyslot area | `(*luks2.Volume).RemoveKeyslot(ctx, slot) error` |

No request/response schema, status code mapping or `scp` permission applies.
See [volumes/api.md](../volumes/api.md) for the general Layer 0 statement
this folder inherits.
