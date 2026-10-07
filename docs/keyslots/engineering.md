# Keyslots — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

## Exported surface

### `*Volume` (`pkg/luks2`)

```go
const MaxKeyslots = 32
type KeyslotParams struct { Slot *int; Priority Priority; KDF KDFParams }
func (v *Volume) AddKeyslot(ctx context.Context, key *Key, pass *enclave.MemoryEnclave, p KeyslotParams) (KeyslotInfo, error)
func (v *Volume) ChangeKeyslot(ctx context.Context, key *Key, pass *enclave.MemoryEnclave, p KeyslotParams) (KeyslotInfo, error)
func (v *Volume) RemoveKeyslot(ctx context.Context, slot int) error
type KeyslotInfo struct { ID int; Type string; KeySize int; Priority Priority; Encryption string; KDF KDFParams }
type Priority int
const (PriorityIgnore Priority = iota; PriorityNormal; PriorityPrefer)
```

`AddKeyslot`/`ChangeKeyslot` need the `*Key` capability from
[volumes](../volumes/engineering.md#exported-surface) because they re-verify
it against the digest under the exclusive lock (the header may have changed
since `Unlock`). `RemoveKeyslot(ctx, slot)` keeps every data-safety guard
(`ErrLastKeyslot`, `ErrKeyslotAreaOverlap`) but drops the authentication
distinction cryptsetup's `luksKillSlot` makes: **removal is guarded, not
authenticated** (DESIGN.md §B.1, owner decision). Authorization is the
caller's policy — the CLI's own passphrase prompt before it calls
`RemoveKeyslot`, or a platform's IAM layer above this library. There is no
separate read-only probe method: checking that a passphrase opens a volume is
`(*Volume).Unlock` followed by `(*Key).Destroy`.

$1

- A volume always keeps at least one keyslot that can open it
  (`ErrLastKeyslot`); only a keyslot bound to every data segment counts
  toward that guard.
- A keyslot's `area` never overlaps another keyslot's area or a data segment
  (`ErrKeyslotAreaOverlap`), checked before any write that could create an
  overlap.
- `AddKeyslot`/`ChangeKeyslot` read the new keyslot back from the written header and
  require it to open to the volume key; one that does not is rolled back and
  the call fails with `ErrWrongKey`. Every keyslot operation
  reads and writes through the one descriptor it locked (device-lock
  invariant: [volumes/engineering.md](../volumes/architecture.md#volume-target-and-activation)).
- `AddKeyslot` returns the slot it wrote (`KeyslotInfo.ID`), chosen under the device lock. Never
  infer the slot from the header afterwards: slots need not be contiguous.

## Cost inheritance

When the caller sets no Argon2 cost, `AddKeyslot` takes it from the
volume's first Argon2 keyslot, and `ChangeKeyslot` keeps the cost
of the slot it rewrites. Either may be below the create floor: a volume
formatted small to stay openable on small hardware stays that way.
`AddKeyslot`/`ChangeKeyslot` report the cost written in the returned
`KeyslotInfo.KDF`.

| Bound | Value | Applies to |
|---|---|---|
| Create floor | `MinArgon2MemoryKB` = 65536 | Costs a caller passes to `Format` or `AddKeyslot` |
| Create ceiling | memory 4 GiB, time 10000, 255 threads | Every keyslot written, so it always reopens |
| Accept floor | 8 KiB | Reading, inheriting, removing |

`ChangeKeyslot` rewrites a SHA-1 keyslot as PBKDF2-SHA256 with a SHA-256 split;
see [fips/architecture.md](../fips/architecture.md#sha-1).

Recovery keyslots have a lower floor of their own: see
[recovery-keys/engineering.md](../recovery-keys/engineering.md#generated-credentials).

## KDF

Each keyslot turns its credential into a wrapping key with its own KDF
(`internal/kdf`, landed H4). A separate PBKDF2 digest checks the recovered
volume key.

| `KDFType` | Notes |
|---|---|
| `argon2id` | Default outside FIPS mode. Time 4, memory 1048576 KiB (1 GiB), 4 threads unless set. |
| `argon2i` | Same parameters. |
| `pbkdf2` | SHA-256 unless `KDFParams.Hash` names another. |
| `pbkdf2-sha256`, `pbkdf2-sha384`, `pbkdf2-sha512` | The hash is in the name. `pbkdf2-sha512` is the default in FIPS 140-3 mode. |
| `pbkdf2-sha1` | Never written: refused with `ErrInvalidArgument`. Existing SHA-1 keyslots are read outside FIPS mode. |

`DefaultKDFType()` returns the default for the current mode. A caller that
names no type but sets an Argon2 cost gets `argon2id`. Salts are 32 random
bytes. FIPS rules: [fips/architecture.md](../fips/architecture.md).

```go
// AddKeyslot: Argon2id at 512 MiB
_, err := v.AddKeyslot(ctx, key, newPass, luks2.KeyslotParams{
	KDF: luks2.KDFParams{Type: luks2.KDFArgon2id, MemoryKiB: 524288},
})

// AddKeyslot: PBKDF2-SHA512 calibrated to 3s
_, err = v.AddKeyslot(ctx, key, newPass, luks2.KeyslotParams{
	KDF: luks2.KDFParams{Type: luks2.KDFPBKDF2, Hash: crypto.SHA512, IterTime: 3 * time.Second},
})
```

`Format` takes the same costs through `FormatParams.KDF`:

```go
// Argon2id at 512 MiB
argon := luks2.FormatParams{
	KDF: luks2.KDFParams{Type: luks2.KDFArgon2id, MemoryKiB: 524288},
}

// PBKDF2-SHA512 calibrated to 3 s
calibrated := luks2.FormatParams{
	KDF: luks2.KDFParams{Type: luks2.KDFPBKDF2, Hash: crypto.SHA512, IterTime: 3 * time.Second},
}

// PBKDF2-SHA512 at a fixed count, no calibration
fixed := luks2.FormatParams{
	KDF: luks2.KDFParams{Type: luks2.KDFPBKDF2, Hash: crypto.SHA512, Iterations: 500_000},
}

err := v.Format(ctx, pass, argon)
```

### PBKDF2 calibration

With no `KDFParams.Iterations`, the count is measured on the formatting machine to
fill `KDFParams.IterTime` (default 2 s). A probe starts at
1000 iterations and doubles until one run takes at least 50 ms, then the count
is extrapolated from that run. Calibration costs about 100 ms.

The result is clamped:

- The floor is the OWASP recommendation for the hash, scaled to the budget:
  600,000 for SHA-256 and 210,000 for SHA-384 and SHA-512 at 2000 ms, never
  below 1000. Calibration measures the defender's hardware, which says
  nothing about the attacker's. On current hardware the measured count is in
  the millions and the floor does not bind. A keyslot for a caller's
  passphrase is never below the 2000 ms floor, whatever `IterTime` asks
  for.
- The ceiling is 100,000,000, the same bound the header reader enforces, so a
  calibrated keyslot always reopens.

If calibration cannot run, `Format` and `AddKeyslot` fail with a
`*KDFCalibrationError` (`ErrKDFCalibration`). There is no fallback constant.

### Fixed iteration counts

`KDFParams.Iterations` writes that exact count, so two machines provisioned
from one spec get the same header. For `Format` and `AddKeyslot` it does not
bypass the floor: below 600,000 (SHA-256) or 210,000 (SHA-384, SHA-512), or above
100,000,000, fails with `ErrInvalidArgument` as a `*KDFCostError{Param,
Value, Min, Max}` carrying the permitted range.
A recovery keyslot has a lower floor:
[recovery-keys/engineering.md](../recovery-keys/engineering.md#generated-credentials).

### The digest

The digest is always PBKDF2, over the volume key, with `FormatParams.Hash`
(default SHA-256). Its count is calibrated to 100 ms of a 64-byte derivation
(`DigestIterationTargetMs`, `DigestCalibrationKeyLen`), which is what
cryptsetup does. Because the input is a random volume key, the digest count
adds no real security; the keyslot KDF is what defends the passphrase.

## Error semantics

| Error | Meaning |
|---|---|
| `ErrWrongKey` | A keyslot was tried and the key did not match the digest: a wrong passphrase, or the right one over damaged key material |
| `ErrKeyslotNotFound`, `ErrInvalidHeader` | No such keyslot, or a malformed keyslot or header; the passphrase may be correct |
| `ErrLastKeyslot` | Removal would leave nothing that opens the volume |
| `ErrKeyslotAreaOverlap` | A keyslot area would overlap another keyslot or a data segment |
| `*KDFCalibrationError` / `ErrKDFCalibration` | PBKDF2 calibration could not run |
| `*KDFCostError` (`Is ErrInvalidArgument`) | A fixed PBKDF2 iteration count, or an Argon2 cost, is outside the permitted range (DESIGN.md §C.3) |
| `ErrInvalidHeader` | Includes a header that asks one unlock for more key derivation than any cryptsetup header can |
| `ErrProtectedMemory` | No locked memory, or more than the process allocator's budget, for a keyslot scan |

## Configuration

`KeyslotParams{Slot, Priority, KDF KDFParams}` ([engineering.md](#exported-surface)
above). A zero `KDFParams` resolves to the library default, or to an inherited
Argon2 cost (see "Cost inheritance").

## Persistence

Keyslot JSON shape (`type`, `key_size`, `af`, `area`, `kdf`, `priority`) is
part of the header schema: [header/engineering.md](../header/engineering.md).
Removing a keyslot drops its number from every digest and token in the same
write; a token left naming no keyslot is kept
([tokens/engineering.md](../tokens/engineering.md)).

`RemoveKeyslot` authenticates with nothing (the caller's policy decides) and
fills the freed area with random bytes, because encrypted key material looks
random and zeroes would show which slots were used.

## Test strategy

Unit tests cover the cost floors/ceilings, inheritance, unlock-order and
removal-guard logic against real temp-file volumes at minimum legal KDF cost
(`kdf_test.go`, `kdfcost_test.go`, `kdfcalibration_test.go`,
`kdfbudget_test.go`, `keyslotcostpolicy_test.go`, `kdfiterations_test.go` and
their `internal/kdf` equivalents, per DECISIONS.md H4). Integration coverage
is the cryptsetup two-way matrix's add, change and remove keyslot rows: [cryptsetup-interop/engineering.md](../cryptsetup-interop/engineering.md).
`internal/kdf` carries its own suite with a 90% floor
(`coverage-floors.txt`); `pkg/luks2`'s unit floor is unchanged by that move.

## Observability

No logging; every failure above is a typed, returned error.
