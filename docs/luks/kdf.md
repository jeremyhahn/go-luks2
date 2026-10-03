# Key Derivation Functions

LUKS2 uses Key Derivation Functions (KDFs) to convert passphrases into cryptographic keys resistant to brute-force attacks.

## Supported KDFs

| KDF | Type | Resistance | Use Case |
|-----|------|------------|----------|
| Argon2id | Memory-hard | Best | Default, recommended |
| Argon2i | Memory-hard | Good | Side-channel protection |
| PBKDF2 | Iterative | Moderate | FIPS compliance, compatibility |

## Argon2id (Recommended)

Argon2id combines Argon2i (data-independent) and Argon2d (data-dependent) for optimal security.

### Parameters

```json
{
  "type": "argon2id",
  "salt": "base64-encoded-32-byte-salt",
  "time": 4,
  "memory": 1048576,
  "cpus": 4
}
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| time | Iterations (time cost) | 4 |
| memory | Memory in KB | 1048576 (1 GB) |
| cpus | Parallelism (threads) | 4 |

### Security Properties

- **Memory-hard**: Requires significant RAM, resists GPU attacks
- **Time-hard**: Multiple iterations increase computation time
- **Parallel**: Uses multiple CPU cores

### Example Configuration

```go
opts := luks2.FormatOptions{
    KDFType:        "argon2id",
    Argon2Time:     4,        // 4 iterations
    Argon2Memory:   1048576,  // 1 GB
    Argon2Parallel: 4,        // 4 threads
}
```

## Argon2i

Data-independent variant, resistant to side-channel attacks.

### Parameters

Same as Argon2id:

```json
{
  "type": "argon2i",
  "salt": "base64...",
  "time": 4,
  "memory": 1048576,
  "cpus": 4
}
```

### Use Cases

- Systems where timing attacks are a concern
- Shared hosting environments
- When Argon2id is not available

## PBKDF2

Password-Based Key Derivation Function 2, using HMAC.

### Parameters

```json
{
  "type": "pbkdf2",
  "salt": "base64-encoded-salt",
  "hash": "sha256",
  "iterations": 4194304
}
```

| Parameter | Description | Typical Value |
|-----------|-------------|---------------|
| hash | Hash algorithm | sha256, sha512 |
| iterations | Number of iterations | Calibrated; several million on current hardware at the 2 s default |

### Supported Hashes

| Hash | Output Size | FIPS Compliant |
|------|-------------|----------------|
| sha1 | 160 bits | No — read in existing keyslots only, never written (`ErrSHA1NotWritten`, see [FIPS.md](../FIPS.md)) |
| sha256 | 256 bits | Yes |
| sha384 | 384 bits | Yes |
| sha512 | 512 bits | Yes |

### Example Configuration

```go
opts := luks2.FormatOptions{
    KDFType:       "pbkdf2",
    HashAlgo:      "sha256",
    PBKDFIterTime: 2000,  // Target 2 seconds
}
```

### FIPS Compliance

PBKDF2 is the only FIPS-approved KDF, and only with SHA-2/SHA-3:

```go
// Check if KDF is FIPS compliant
if luks2.IsFIPSCompliantKDF("pbkdf2") {
    // Use for FIPS environments
}
```

`IsFIPSCompliantKDF("pbkdf2-sha1")` returns `false`; no keyslot is created
with SHA-1 in any mode (`ErrSHA1NotWritten`), and deriving through an existing
SHA-1 keyslot returns `ErrFIPSNotApproved` while the process runs in FIPS
140-3 mode. Argon2i
and Argon2id are refused in FIPS mode for the same reason, including when
`CreateKDF` reaches Argon2id as its default. See [FIPS.md](../FIPS.md) for the
full policy and the legacy-header exemption.

## Iteration Calibration

The iteration count is **measured on the machine doing the formatting**, to fill
the requested time budget. It is written into the header at format time and is
the entire cost an offline attacker pays per passphrase guess, so a count that
is too low is permanent for that volume — no later change reaches a header that
is already on disk.

### Automatic Calibration

```go
// Target 2 second unlock time
opts := luks2.FormatOptions{
    KDFType:       "pbkdf2",
    PBKDFIterTime: 2000,  // milliseconds, 1..600000
}
```

### Explicit iteration count

Calibration answers "how much work fits in N milliseconds of *this* machine's
time", so it yields a different number on every host. Where a container must be
reproducible — provisioning two machines from one specification, or comparing
bytes against another implementation — the count can be pinned instead:

```go
opts := luks2.FormatOptions{
    KDFType:         "pbkdf2",
    HashAlgo:        "sha512",
    PBKDFIterations: 500_000, // bypasses calibration; PBKDFIterTime is ignored
}
```

`AddKeyOptions.PBKDFIterations` does the same for a new keyslot.

**It does not bypass the iteration floor.** cryptsetup's
`--pbkdf-force-iterations` bypasses its own minimum; this deliberately does not,
because a floor any caller can argue around is not a floor and nothing can
strengthen a keyslot that is already on disk. A count below the floor for the
chosen hash is refused with `ErrPBKDFIterationsTooLow`, and one above
`maxKDFIterations` — the ceiling applied when a header is read back — with
`ErrPBKDFIterationsTooHigh`. Both are carried on a `*PBKDFIterationsError` that
reports the permitted range:

| Hash | Minimum |
|---|---|
| sha256 | 600000 |
| sha384 | 210000 |
| sha512 | 210000 |
| any other | 1000 |

### The floor and library-generated credentials

The iteration floor above applies to credentials a **caller** supplies. It does
not apply to credentials **this library generated** — recovery keys and enrolled
provider keys, which are 256 CSPRNG bits.

An iteration count buys exactly one thing: it multiplies the cost of each guess
in an offline *search*. That is decisive for a human-chosen passphrase, drawn
from a space an attacker can enumerate. For 256 random bits there is no
candidate list, so there is no search, so there is nothing to multiply.

Concretely, the floor made systemd's own parameters unwritable: systemd enrolls
`pbkdf2 / sha512 / 1000`, and the sha512 floor is 210000, so this library could
not reproduce a systemd-enrolled header even when told exactly what to write.

The exemption is **structural, not a flag**:

- It travels as an unexported type (`keyslotCostPolicy`) on an unexported
  function. There is no `Force` or `SkipFloor` field, and none may be added — a
  floor a caller can argue around is not a floor.
- Its zero value is the strict policy, so anything that forgets to choose gets
  the floor.
- The exempt path **keeps a floor**: `minPBKDF2Iterations` (1000), LUKS2's own
  minimum and exactly what systemd writes. Zero and negative are still refused,
  and the ceiling is unchanged.

> The same shape — "the input is a full-entropy CSPRNG secret, so the iteration
> count defends nothing" — was argued about the master-key *digest* and
> reverted. The logic was sound; the *evidence* was not, because the measurement
> was taken with a flag that wrote its own answer. Check what is actually being
> enumerated before reusing the argument.

### Manual Benchmark

```go
// Benchmark for 2 seconds
iterations, err := luks2.BenchmarkPBKDF2("sha256", 32, 2000)
if err != nil {
    // Calibration is fail-closed: it returns ErrKDFCalibration rather than a
    // weakened default. Do not substitute a constant here.
    return err
}
fmt.Printf("Calibrated iterations: %d\n", iterations)
```

### How the calibration works

A probe derivation starts at 1000 iterations and **doubles** until it runs long
enough to be timed reliably (tens of milliseconds — long enough that one
scheduler preemption is noise rather than the measurement). The count for the
requested budget is extrapolated from that probe using the full measured
duration, never a truncated millisecond count. Calibration therefore costs about
100 ms once per format, whatever the budget is.

Two clamps bound the result:

- **A security floor.** A calibrated count answers "how much work fits in the
  budget on *this* machine", which is a fact about the defender's hardware; the
  attacker's hardware is unrelated and is not slow. The count is therefore never
  below the OWASP recommendation for the hash, scaled to the requested budget —
  600,000 for SHA-256 and 210,000 for SHA-384/512 at the 2000 ms default
  (SHA-1 is never written, #239). On current hardware the measured count is several million and
  the floor never binds; it binds on hardware roughly ten times slower.
- **A header ceiling**, the same one the keyslot validator applies when the
  header is read back, so a calibrated count can never produce a keyslot this
  library would then refuse to open.

A calibration that cannot be performed **fails**: `BenchmarkPBKDF2` returns a
`*KDFCalibrationError` (matching `ErrKDFCalibration`) and no count. It never
returns a plausible-looking constant with a `nil` error — doing that is how a
volume ends up permanently weaker than the caller asked for, with nothing to
say so.

## Salt Generation

Each keyslot uses a unique random salt:

- 32 bytes for Argon2
- 32 bytes for PBKDF2
- Generated using cryptographic random

```go
// Salt is auto-generated during Format
// Never reuse salts across keyslots
```

## Digest KDF

The master key digest always uses PBKDF2:

```json
{
  "digests": {
    "0": {
      "type": "pbkdf2",
      "hash": "sha256",
      "iterations": 100000,
      "salt": "base64...",
      "digest": "base64..."
    }
  }
}
```

This is separate from the keyslot KDF and verifies the decrypted master key.

### The digest cost is calibrated, not fixed

`DigestIterations` used to be a constant. It is now calibrated to
`DigestIterationTargetMs` (100 ms), matching cryptsetup, which calibrates the
digest rather than pinning it.

**This parameter buys essentially no security.** The digest verifies a candidate
*master key* — 512 bits from a CSPRNG — so there is no guessable input for an
iteration count to slow down and no offline search for it to multiply. The count
that defends a guessable secret is the **keyslot** KDF's, and its floor is
non-negotiable. What this controls is unlock latency and parity with cryptsetup.

The 100 ms target was measured, not chosen. Across 14 default containers on one
host, converting each recorded count by that machine's PBKDF2 rate:

| Hash | Digest iterations | Implied time |
|---|---|---|
| sha512 | 317750–328090 | 96.7–101.0 ms |
| sha256 | 493679–518071 | 47.1–49.5 ms |

The two hashes look like different targets and are not: cryptsetup benchmarks a
fixed **64-byte** derivation whatever the hash, and under sha256 that is two
PBKDF2 blocks per iteration rather than one. Re-measured at 64 bytes both land on
100 ms (sha512 100.0, sha256 101.0). Hence `DigestCalibrationKeyLen = 64`.

The digest cost is also independent of the keyslot budget — at `--iter-time`
500/2000/8000 ms the keyslot count scales 16x while the digest holds between
452753 and 468951 — which is why it needs its own target.

> **Measurement trap.** A container formatted with `--pbkdf-force-iterations`
> reports a digest of exactly the forced value: that flag pins the *digest* as
> well as the keyslot. Measuring that way shows a digest of 1000 and invites the
> conclusion that cryptsetup hardcodes it. Take this measurement on **default**
> containers or not at all.

## Performance Comparison

| KDF | Memory | 1GB Argon2 | Comments |
|-----|--------|-----------|----------|
| Argon2id | High | ~1s | Best security |
| Argon2i | High | ~1s | Side-channel safe |
| PBKDF2 | Low | ~2s | FIPS compatible |

## Security Recommendations

### For New Volumes

Use Argon2id with:
- Memory: 1 GB or more
- Time: 4+ iterations
- CPUs: Match system cores

### For FIPS Compliance

Use PBKDF2 with:
- Hash: SHA-256 or SHA-512
- Iterations: calibrated for 2+ seconds (`PBKDFIterTime: 2000`), never a
  hand-picked constant. The floor is 600,000 for SHA-256 and 210,000 for
  SHA-384/512; current hardware earns several million.

### For Low-Memory Systems

Use PBKDF2 or Argon2 with reduced memory:
- Argon2 memory: 256 MB minimum
- PBKDF2: No memory requirement
