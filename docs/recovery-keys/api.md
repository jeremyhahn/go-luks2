# Recovery keys — API

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is an embedded Go
library; it has no REST, gRPC, QUIC, MCP or Unix-socket transport.

| Capability | Embedded (Go call) |
|---|---|
| Generate a key, no volume touched | `NewRecoveryKey(opts ...RecoveryKeyOption) (*RecoveryKey, error)` |
| Print the key | `(*RecoveryKey).WriteTo(io.Writer) (int64, error)` |
| Add a generated key to a volume | `(*Volume).AddRecoveryKey(ctx, key *Key, rk *RecoveryKey, KeyslotParams) (Enrollment, error)` |
| Verify a key still opens the volume | `(*Volume).Unlock(ctx, credential)`, then `(*Key).Destroy` |
| Parse typed or pasted input | `ParseRecoveryKey(text enclave.ByteAccess) (enclave.ByteAccess, error)` |
| Choose the format | `WithRecoveryFormat(RecoveryKeyFormat) RecoveryKeyOption`: `RecoveryDashed` (the default), `RecoveryHex` or `RecoveryBase64`; `ParseRecoveryKeyFormat(name string) (RecoveryKeyFormat, error)` reads the name `RecoveryKeyFormat.String` prints |
| Choose the length | `WithRecoveryLength(n int) RecoveryKeyOption`, random bytes, at least `DefaultRecoveryKeyLength` (32) and no longer rendered than `MaxPassphraseLength` |
| Inspect a key | `(*RecoveryKey).Format() RecoveryKeyFormat`, `(*RecoveryKey).Hash() string` (the printed digest) |
| Discard a key | `(*RecoveryKey).Destroy()`, idempotent and nil-safe |
| What was enrolled | `Enrollment{Keyslot KeyslotInfo; Token int}`; the token's type is `TokenTypeRecovery` (`systemd-recovery`) |

| Error | Returned when |
|---|---|
| `ErrInvalidArgument` | An unknown format, or a length outside the bounds above |
| `*OrphanedKeyslotError`, `ErrOrphanedKeyslot` | The token write failed and the keyslot it would have named could not be removed |

No request/response schema, status code mapping or `scp` permission applies.
See [volumes/api.md](../volumes/api.md) for the general Layer 0 statement
this folder inherits.
