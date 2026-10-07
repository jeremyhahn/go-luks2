# FIPS 140-3 — API

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is a Layer 0 library (docs/00
§L1 exemption); REST/gRPC/QUIC/MCP/Unix: not applicable.

| Capability | Embedded (Go call) |
|---|---|
| Get the default KDF for the current mode | `DefaultKDFType() string` |
| Check whether a KDF type is FIPS-approved | `IsFIPSCompliantKDF(kdfType string) bool` |
| Import a non-approved volume into FIPS compliance | `MigrateToFIPS(device, passphrase, *FIPSMigrationOptions) (*FIPSMigrationResult, error)` |

**No CLI verb**: `MigrateToFIPS` is library-only (see [cli.md](cli.md)). No
request/response schema, status code mapping or `scp` permission applies at
any transport. See [volumes/api.md](../volumes/api.md) for the general
Layer 0 statement this folder inherits.
