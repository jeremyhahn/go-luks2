# dm-crypt activation — API

> **Status: NORMATIVE** · Last verified: 2026-10-12 against 7ee49b8
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is an embedded Go
library; it has no REST, gRPC, QUIC, MCP or Unix-socket transport.

| Capability | Embedded (Go call) |
|---|---|
| Map a volume key as a dm-crypt target | `dmcrypt.Activate(ctx, v *luks2.Volume, key *luks2.Key, name string) (*Mapping, error)` |
| Remove a mapping | `dmcrypt.Deactivate(ctx, name string) error` |
| Find a live mapping | `dmcrypt.Lookup(ctx, name string) (*Mapping, error)` |
| Preflight the kernel keyring | `dmcrypt.CheckKeyring(ctx) error` |
| Validate a mapping name | `dmcrypt.ValidateName(name string) error` |
| The `/dev/mapper` path of a mapping | `(*dmcrypt.Mapping).Path() string` |

No request/response schema, status code mapping or `scp` permission applies.
The signatures, invariants and error table are in
[engineering.md](engineering.md#exported-surface). See
[volumes/api.md](../volumes/api.md) for the general Layer 0 statement this
folder inherits.
