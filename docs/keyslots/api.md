# Keyslots — API

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is an embedded Go
library; it has no REST, gRPC, QUIC, MCP or Unix-socket transport.

| Capability | Embedded (Go call) |
|---|---|
| Test a passphrase | `(*Volume).Unlock(ctx, pass)`, then `(*Key).Destroy()` |
| Add a passphrase | `(*Volume).AddKeyslot(ctx, key, pass, KeyslotParams) (KeyslotInfo, error)` |
| Change a passphrase in place | `(*Volume).ChangeKeyslot(ctx, key, pass, KeyslotParams) (KeyslotInfo, error)` |
| Set a keyslot's priority | `KeyslotParams.Priority`: `PriorityIgnore`, `PriorityNormal` or `PriorityPrefer`; the zero value `PriorityDefault` makes a new slot normal and leaves a changed slot's priority as it was |
| Remove a keyslot | `(*Volume).RemoveKeyslot(ctx, slot) error` (guarded, not authenticated) |
| List keyslots | `(*Header).Keyslots() []KeyslotInfo`, from `(*Volume).Header(ctx)` |

No request/response schema, status code mapping or `scp` permission applies:
there is no transport boundary inside this call. See
[volumes/api.md](../volumes/api.md) for the general Layer 0 statement this
folder inherits.
