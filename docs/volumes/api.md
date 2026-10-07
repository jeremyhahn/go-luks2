# Volumes — API

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

go-luks2 is a Layer 0 library (`docs/00-ownership-and-sdk-boundary.md` §L1
exemption): it is consumed as an ordinary Go library, not as a stack service,
so it carries no §R row and the six-transport tier system in
`api-conventions.md` does not apply to it.

| Transport | Form |
|---|---|
| Embedded (Go call) | `pkg/luks2` directly; see [engineering.md](engineering.md#exported-surface) for the volume-lifecycle surface |
| Unix socket | Not applicable, Layer 0 library (docs/00 §L1 exemption) |
| REST | Not applicable, Layer 0 library (docs/00 §L1 exemption) |
| gRPC | Not applicable, Layer 0 library (docs/00 §L1 exemption) |
| QUIC | Not applicable, Layer 0 library (docs/00 §L1 exemption) |
| MCP | Not applicable, Layer 0 library (docs/00 §L1 exemption) |

There is no request/response schema, status code mapping or `scp` permission
to document here: this library has no process boundary of its own. A consumer
that re-exposes volume operations over one of those transports (for example
go-trusted-platform's `services/luks` re-export frontage) documents that
mapping in its own repository, not here.

A command-line process is not a transport in this sense; `cmd/luks2` is
documented in [cli.md](cli.md).
