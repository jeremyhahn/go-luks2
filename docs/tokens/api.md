# Tokens — API

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is a Layer 0 library (docs/00
§L1 exemption); REST/gRPC/QUIC/MCP/Unix: not applicable.

| Capability | Embedded (Go call) |
|---|---|
| List / read tokens | `(*Volume).Header(ctx) (*Header, error)`, then `(*Header).Tokens() map[int]Token` |
| Write / replace / remove a token | `(*Volume).AddToken`, `SetToken`, `RemoveToken` |
| Enroll a `KeyProvider`-backed credential | `(*Volume).Enroll(ctx, key, provider, KeyslotParams) (Enrollment, error)` |
| Unlock through a `KeyProvider` | `(*Volume).UnlockWithProvider(ctx, provider) (*Key, error)`, then `dmcrypt.Activate` |
| Build a provider | `keyprovider.NewCommand`, `keyprovider.NewFIDO2` |
| Rebuild a provider from a stored token | `keyprovider.FromToken(token, opts...)` |

No request/response schema, status code mapping or `scp` permission applies.
See [volumes/api.md](../volumes/api.md) for the general Layer 0 statement
this folder inherits.
