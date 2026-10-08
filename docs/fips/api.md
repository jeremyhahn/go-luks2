# FIPS 140-3 — API

> **Status: NORMATIVE** · Last verified: 2026-10-08 against v1.0.0-rc.2 (12a364e) plus the polish/p-fips change
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is a Layer 0 library (docs/00
§L1 exemption); REST/gRPC/QUIC/MCP/Unix: not applicable.

| Capability | Embedded (Go call) |
|---|---|
| Get the default KDF for the current mode | `DefaultKDFType() KDFType` (`KDFPBKDF2` in FIPS mode, `KDFArgon2id` otherwise) |
| Check, before any device is touched, whether a KDF may be used in this process | `(KDFParams).Validate() error` (refuses an Argon2 KDF, named or implied by its cost, in FIPS mode with `ErrFIPSNotApproved`) |
| Recognize a volume FIPS mode cannot open until it is imported | `(*Volume).Unlock` in a FIPS process fails with a `*FIPSImportRequiredError` naming the non-approved keyslots and digests; `errors.Is(err, ErrFIPSImportRequired)` |
| Import a non-approved volume into FIPS compliance | `(*Volume).MigrateToFIPS(ctx context.Context, pass *enclave.MemoryEnclave, p MigrateParams) (*Migration, error)` |

`MigrateParams.KeepNonApproved` keeps the original keyslots (a
half-migration: `Migration.Complete` is then false and
`Migration.RetainedNonApproved` lists them); `MigrateParams.KDF` sets the new
PBKDF2 keyslot's cost and hash (`Hash`'s zero value is SHA-256). A failed
migration matches `ErrFIPSMigration` and unwraps to a `*FIPSMigrationError`
whose `Stage` says where it stopped and whose `State` says what the volume
was left as; called from a FIPS process it fails at `Stage` "precondition"
without touching the device.

**No CLI verb**: `MigrateToFIPS` is library-only (see [cli.md](cli.md)). No
request/response schema, status code mapping or `scp` permission applies at
any transport. See [volumes/api.md](../volumes/api.md) for the general
Layer 0 statement this folder inherits.
