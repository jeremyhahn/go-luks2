# FIPS 140-3

`go-luks2` is built and tested against the Go Cryptographic Module so that it can
be consumed from FedRAMP / PCI DSS / HIPAA regulated deployments.

## CI gate

The `FIPS` job in `.github/workflows/ci.yml` builds and runs the full test suite
with:

```
GOFIPS140=latest
GODEBUG=fips140=only
```

`fips140=on` loads the module but still *permits* non-approved algorithms, so a
regulated path using MD5 or SHA-1 would report green. `fips140=only` makes
non-approved operations return errors or panic, which is what the gate exists to
catch. The job runs `go build ./...` and `go test ./...` — full scope, no build
tags, no skipped packages.

## Approved KDFs

`IsFIPSCompliantKDF` reports which KDF types this library considers approved:

| KDF type | FIPS-approved | Notes |
|---|---|---|
| `pbkdf2` | yes | derives with SHA-256 unless `FormatOptions.HashAlgo` overrides it |
| `pbkdf2-sha256` | yes | recommended |
| `pbkdf2-sha384` | yes | |
| `pbkdf2-sha512` | yes | |
| `pbkdf2-sha1` | **no** | legacy header interop only — see the exemption below |
| `argon2i` | no | refused in FIPS mode |
| `argon2id` | no | refused in FIPS mode; library default otherwise |

## Enforcement: Argon2 is refused in FIPS mode

Argon2 is implemented in pure Go by `golang.org/x/crypto` (BLAKE2b) and never
enters the Go Cryptographic Module, so `GODEBUG=fips140=only` cannot reject it
and the CI gate cannot fail on it. Left alone, a FIPS-mode process would derive
volume keys with a non-approved KDF — by default, since `CreateKDF` falls back
to `argon2id` — while the gate above reported green. `GODEBUG` is not a
sufficient boundary for a KDF the module never sees, so the library enforces it:

`requireFIPSApprovedKDF` in `pkg/luks2/kdf.go` returns
`&CryptoError{Err: ErrFIPSNotApproved}` for `argon2i` and `argon2id` whenever
`crypto/fips140.Enabled()` is true. It is called from:

- `DeriveKey`, before the salt is decoded — so an externally supplied header
  cannot make a FIPS-mode process run a non-approved KDF;
- `CreateKDF`, after the empty-`KDFType` default is resolved — so
  `FormatOptions{}` cannot silently write an Argon2id keyslot in a FIPS-mode
  process. A FIPS caller must select an approved KDF explicitly rather than have
  one substituted for them.

**Effect on callers.** A FIPS-mode process can neither format nor unlock an
Argon2-backed volume, and Argon2id has been the stock cryptsetup LUKS2 default
since 2.0, so that covers most volumes in the field. This is the compliance
position, not an oversight: a process that asked the Go runtime to reject
non-approved cryptography should not then derive regulated keys with a
non-approved KDF. Such a volume must be re-keyed to `pbkdf2-sha256` or better,
or opened by a non-FIPS process. Outside FIPS mode Argon2id remains the default
and nothing changes.

## Exemption: PBKDF2-HMAC-SHA1 for legacy LUKS headers

**Scope.** `getPBKDF2HashFunc("sha1")` in `pkg/luks2/kdf.go`, reachable through
`DeriveKey`, `BenchmarkPBKDF2` and `CreateKDF` (the `pbkdf2-sha1` alias, or the
`pbkdf2` type with `HashAlgo: "sha1"`). Nothing else in this repository uses
SHA-1 or any other non-approved primitive; the anti-forensic splitter
(`pkg/luks2/antiforensic.go`) already accepts only SHA-256 and SHA-512.

**Why the primitive is needed.** A LUKS keyslot records the hash its PBKDF2
digest was derived with, in the LUKS1 `hash-spec` header field and in the LUKS2
JSON keyslot `kdf.hash` field. cryptsetup used SHA-1 as the LUKS1 default until
1.7.0, so volumes formatted by older releases carry `sha1` and can only be
unlocked by recomputing PBKDF2-HMAC-SHA1 over the passphrase. This project's
`CLAUDE.md` requires interfacing correctly with the cryptsetup userspace tools,
so the primitive cannot simply be deleted without losing the ability to open
those volumes.

**Why it is not a compliance violation.** The exemption covers reading an
externally-defined on-disk format, not the protection of regulated data by this
library's own choices. New volumes should be formatted with `pbkdf2-sha256` or
better (or Argon2id outside FIPS); `IsFIPSCompliantKDF("pbkdf2-sha1")` returns
`false` so callers cannot be told otherwise.

**How it is isolated from the FIPS-gated path.** `getPBKDF2HashFunc` checks
`crypto/fips140.Enabled()` and returns `ErrFIPSNotApproved` before the call can
reach `golang.org/x/crypto/pbkdf2`. The Go Cryptographic Module permits PBKDF2
only with SHA-2 and SHA-3 and panics with

```
crypto/pbkdf2: use of hash functions other than SHA-2 or SHA-3 is not allowed
in FIPS 140-only mode
```

under `GODEBUG=fips140=only`. The runtime guard means the SHA-1 derivation never
executes in a FIPS-mode process — a stronger boundary than a build tag, because
it holds for every FIPS deployment of this library rather than only for binaries
built with a particular tag, and it lets the FIPS CI job keep exercising the
whole tree. Outside FIPS mode the behavior is unchanged.

`crypto/fips140.Enabled()` reports true for both `fips140=on` and `fips140=only`
and there is no exported way to distinguish them, so SHA-1 is refused under `on`
as well. That is deliberate: a process running in FIPS mode should not derive
keys with a non-approved primitive regardless of whether the module would have
tolerated it.

**Effect on callers.** A FIPS-mode process that opens a legacy `sha1` volume gets
`ErrFIPSNotApproved` (checkable with `errors.Is`) rather than a panic. Such a
volume must be re-keyed to an approved hash — or opened by a non-FIPS process —
before it can be used in a regulated deployment.

## References

- Go FIPS 140-3 mode: https://go.dev/doc/security/fips140
- `crypto/fips140` — `Enabled` reports FIPS 140-3 mode for both `on` and `only`
- `golang.org/x/crypto/pbkdf2` — rejects hashes other than SHA-2/SHA-3 in
  FIPS 140-only mode
- NIST SP 800-132 — Recommendation for Password-Based Key Derivation
- LUKS1 on-disk format specification — `hash-spec` header field
- LUKS2 on-disk format specification — keyslot `kdf.hash` JSON field
- `cryptsetup(8)` — `--hash`, `--pbkdf`
