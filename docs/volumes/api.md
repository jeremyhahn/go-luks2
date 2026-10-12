# Volumes — API

> **Status: NORMATIVE** · Last verified: 2026-10-12 against 7ee49b8
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is an embedded Go
library; it has no REST, gRPC, QUIC, MCP or Unix-socket transport.

| Transport | Form |
|---|---|
| Embedded (Go call) | `pkg/luks2` directly; see [engineering.md](engineering.md#exported-surface) for the volume-lifecycle surface |
| Unix socket | None |
| REST | None |
| gRPC | None |
| QUIC | None |
| MCP | None |

There is no request/response schema, status code mapping or `scp` permission
to document here: this library has no process boundary of its own. A consumer
that re-exposes volume operations over one of those transports (for example
go-trusted-platform's `services/luks` re-export frontage) documents that
mapping in its own repository, not here.

A command-line process is not a transport in this sense; `cmd/luks2` is
documented in [cli.md](cli.md).
