# FIPS 140-3 — API

> **Status: NORMATIVE** · Last verified: 2026-10-12 against a9c840c
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is an embedded Go
library; it has no REST, gRPC, QUIC, MCP or Unix-socket transport.

| Capability | Embedded (Go call) |
|---|---|
| Get the default KDF for the current mode | `DefaultKDFType() KDFType` (`KDFPBKDF2` in FIPS mode, `KDFArgon2id` otherwise) |
| Check, before any device is touched, whether a KDF may be used in this process | `(KDFParams).Validate() error` (refuses an Argon2 KDF, named or implied by its cost, in FIPS mode with `ErrFIPSNotApproved`) |
| Recognize a volume FIPS mode cannot open until it is imported | `(*Volume).Unlock` in a FIPS process fails with a `*FIPSImportRequiredError` naming the non-approved keyslots and digests; `errors.Is(err, ErrFIPSImportRequired)` |
| Import a non-approved volume into FIPS compliance | `(*Volume).MigrateToFIPS(ctx context.Context, pass enclave.ByteAccess, p MigrateParams) (*Migration, error)` |

`MigrateParams.KeepNonApproved` keeps the original keyslots (a
half-migration: `Migration.Complete` is then false and
`Migration.RetainedNonApproved` lists them); `MigrateParams.KDF` sets the new
PBKDF2 keyslot's cost and hash (`Hash`'s zero value is SHA-256). A failed
migration matches `ErrFIPSMigration` and unwraps to a `*FIPSMigrationError`
whose `Stage` says where it stopped and whose `State` says what the volume
was left as; called from a FIPS process it fails at `Stage` "precondition"
without touching the device.

## Import a volume

Open the volume read-write and call `MigrateToFIPS` with its passphrase, from
a process that is not in FIPS mode and has already called
`enclave.HardenProcess` ([key custody](../volumes/engineering.md#key-custody-detail)):

```go
v, err := luks2.Open(ctx, "/dev/sdb1")
if err != nil {
	return err
}
defer v.Close()

// pass is the passphrase, held in an enclave.ByteAccess.
res, err := v.MigrateToFIPS(ctx, pass, luks2.MigrateParams{})
// res.Complete: no keyslot or digest FIPS mode cannot run remains
```

`Migration.Keyslot` is the approved keyslot the passphrase now opens,
`MigratedDigests` the digests rewritten to PBKDF2, and `RemovedKeyslots` the
non-approved keyslots removed.

**No CLI verb**: `MigrateToFIPS` is library-only (see [cli.md](cli.md)). No
request/response schema, status code mapping or `scp` permission applies at
any transport. See [volumes/api.md](../volumes/api.md) for the general
Layer 0 statement this folder inherits.
