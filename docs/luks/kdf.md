# Key derivation

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

Each keyslot turns its credential into a wrapping key with its own KDF. A
separate PBKDF2 digest checks the recovered volume key.

## KDF types

| `KDFType` | Notes |
|---|---|
| `argon2id` | Default outside FIPS mode. Time 4, memory 1048576 KiB (1 GiB), 4 threads unless set. |
| `argon2i` | Same parameters. |
| `pbkdf2` | SHA-256 unless `FormatOptions.HashAlgo` or `AddKeyOptions.Hash` names another. |
| `pbkdf2-sha256`, `pbkdf2-sha384`, `pbkdf2-sha512` | The hash is in the name. `pbkdf2-sha512` is the default in FIPS 140-3 mode. |
| `pbkdf2-sha1` | Never written: refused with `ErrSHA1NotWritten`. Existing SHA-1 keyslots are read outside FIPS mode. |

`DefaultKDFType()` returns the default for the current mode. A caller that
names no type but sets an Argon2 cost gets `argon2id`. Salts are 32 random
bytes. FIPS rules are in [FIPS.md](../FIPS.md).

```go
// Argon2id at 512 MiB
argon := luks2.FormatOptions{Device: dev, Passphrase: pass,
	KDFType: "argon2id", Argon2Memory: 524288}

// PBKDF2-SHA512 calibrated to 3 s
calibrated := luks2.FormatOptions{Device: dev, Passphrase: pass,
	KDFType: "pbkdf2-sha512", PBKDFIterTime: 3000}

// PBKDF2-SHA512 at a fixed count, no calibration
fixed := luks2.FormatOptions{Device: dev, Passphrase: pass,
	KDFType: "pbkdf2-sha512", PBKDFIterations: 500_000}
```

## PBKDF2 calibration

With no `PBKDFIterations`, the count is measured on the formatting machine to
fill `PBKDFIterTime` (default 2000 ms, accepted 1–600000). A probe starts at
1000 iterations and doubles until one run takes at least 50 ms, then the count
is extrapolated from that run. Calibration costs about 100 ms.

The result is clamped:

- The floor is the OWASP recommendation for the hash, scaled to the budget:
  600,000 for SHA-256 and 210,000 for SHA-384 and SHA-512 at 2000 ms, never
  below 1000. Calibration measures the defender's hardware, which says nothing
  about the attacker's. On current hardware the measured count is in the
  millions and the floor does not bind.
- The ceiling is 100,000,000, the same bound the header reader enforces, so a
  calibrated keyslot always reopens.

If calibration cannot run, `BenchmarkPBKDF2` and `Format` fail with a
`*KDFCalibrationError` (`ErrKDFCalibration`). There is no fallback constant.

## Fixed iteration counts

`PBKDFIterations` on `FormatOptions`, `AddKeyOptions` or `RecoveryKeyOptions`
writes that exact count, so two machines provisioned from one spec get the same
header. On `FormatOptions` and `AddKeyOptions` it does not bypass the floor:
below 600,000 (SHA-256) or 210,000 (SHA-384, SHA-512) fails with
`ErrPBKDFIterationsTooLow`, above 100,000,000 with `ErrPBKDFIterationsTooHigh`.
Both come as a `*PBKDFIterationsError` carrying the permitted range.
`RecoveryKeyOptions` has a lower floor, below.

### Generated credentials

Recovery keys are random bytes drawn by the library, so there is no offline
search for an iteration count to slow down. For keyslots written by
`AddRecoveryKey` the floor is 1000, which is what systemd writes (`pbkdf2`,
`sha512`, 1000). That holds for any `RecoveryKeyOptions.Length`, including
lengths far below the default 32 bytes, since no minimum length is enforced.
`EnrollKeyProvider` keeps the full floor. The exemption is an unexported
policy type; no exported option selects it.

## The digest

The digest is always PBKDF2, over the volume key, with `FormatOptions.HashAlgo`
(default `sha256`). Its count is calibrated to 100 ms of a 64-byte derivation
(`DigestIterationTargetMs`, `DigestCalibrationKeyLen`), which is what
cryptsetup does. Because the input is a random volume key, the digest count adds
no real security; the keyslot KDF is what defends the passphrase.
