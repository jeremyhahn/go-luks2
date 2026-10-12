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
| Parse typed or pasted input | `ParseRecoveryKey(text *enclave.MemoryEnclave) (*enclave.MemoryEnclave, error)` |

No request/response schema, status code mapping or `scp` permission applies.
See [volumes/api.md](../volumes/api.md) for the general Layer 0 statement
this folder inherits.
