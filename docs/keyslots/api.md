# Keyslots — API

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is a Layer 0 library (docs/00
§L1 exemption); REST/gRPC/QUIC/MCP/Unix: not applicable.

| Capability | Embedded (Go call) |
|---|---|
| Test a passphrase | `(*Volume).Unlock(ctx, pass)`, then `(*Key).Destroy()` |
| Add a passphrase | `(*Volume).AddKeyslot(ctx, key, pass, KeyslotParams) (KeyslotInfo, error)` |
| Change a passphrase in place | `(*Volume).ChangeKeyslot(ctx, key, pass, KeyslotParams) (KeyslotInfo, error)` |
| Remove a keyslot | `(*Volume).RemoveKeyslot(ctx, slot) error` (guarded, not authenticated) |
| List keyslots | `(*Header).Keyslots() []KeyslotInfo`, from `(*Volume).Header(ctx)` |

No request/response schema, status code mapping or `scp` permission applies:
there is no transport boundary inside this call. See
[volumes/api.md](../volumes/api.md) for the general Layer 0 statement this
folder inherits.
