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
| Test one keyslot by number | `(*Volume).UnlockKeyslot(ctx, slot, pass) (*Key, error)`; a slot that does not exist or is not bound to the data segment is `ErrKeyslotNotFound`, before any derivation |
| Set a keyslot's KDF cost | `KeyslotParams.KDF`, a `KDFParams` (`KDFParams.Validate`); `KDFType` is `KDFPBKDF2`, `KDFArgon2id` or `KDFArgon2i`; the zero value is `DefaultKDFType()`, named by `DefaultKDFSpec()` |

The keyslot limit is `MaxKeyslots` (32, ids 0–31).

| Error | Returned when |
|---|---|
| `ErrWrongKey` | A keyslot was tried and the key did not match its digest |
| `ErrKeyslotNotFound` | No such keyslot, or one that cannot be tried |
| `ErrNoKeyslots` | No bound keyslot the scan may try (every one is `ignore`, or none exists) |
| `ErrLastKeyslot` | `RemoveKeyslot` would remove the last bound keyslot |
| `ErrKeyslotAreaOverlap` | A keyslot area overlaps another keyslot or a data segment |
| `*KDFCostError` | A KDF cost is outside its permitted range (`Is ErrInvalidArgument`) |
| `*KDFCalibrationError`, `ErrKDFCalibration` | PBKDF2 calibration could not run |

No request/response schema, status code mapping or `scp` permission applies:
there is no transport boundary inside this call. See
[volumes/api.md](../volumes/api.md) for the general Layer 0 statement this
folder inherits.
