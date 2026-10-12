# cryptsetup interop — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-12 against a9c840c and cryptsetup 2.7.5
> Conflicts with this document are defects. Fix them here first.

go-luks2 does not define its own on-disk format: the format is cryptsetup's,
and a header this library writes must open in cryptsetup and the reverse.
This folder covers the compatibility *policy* (what counts as a breaking
change, and when this library is allowed to be stricter than cryptsetup) and
the measured interop matrix. Every other feature folder's "what cryptsetup
does the same way" detail links back here rather than repeating the matrix.

## The problem and the shape chosen

Two tools writing one on-disk format need an explicit boundary for "we are
allowed to differ here" versus "this must match exactly," or every stricter
check this library adds becomes a silent interop risk. The policy below
exists so that a refusal this library adds is reviewed against one question —
does it stop a cryptsetup-written volume from opening, or only make this
library refuse to create something cryptsetup would have allowed — rather
than being decided ad hoc per feature.

## Rejected alternatives

- **Dropping a cryptsetup `--pbkdf` value (`argon2i`).** Rejected: stricter
  than cryptsetup is fine, incompatibility is not, and a script doing
  `--pbkdf argon2i` must work. `argon2i` is a public KDF type
  (`KDFArgon2i`, `pkg/luks2/kdf.go`) and a `--pbkdf` value
  (`internal/cli/kdfflags.go`).
- **Matching cryptsetup in every behaviour.** Rejected row by row: each
  refusal in "Stricter than cryptsetup", below, gives its reason, and none
  stops a cryptsetup volume from opening.
- **Moving the four white-box integration files into
  `test/integration/interop/`.** Rejected: each reaches a security- or
  determinism-relevant seam, and moving it would mean exporting that seam
  outside `pkg/luks2` (see [Component boundaries](#component-boundaries)).

## Versioning policy

See [README.md](../README.md#versioning-policy) for the version-bump rules
(what counts as breaking, pre-1.0 numbering). What is specific to interop:
**the on-disk format is cryptsetup's.** A header go-luks2 writes must open in
cryptsetup and the reverse; breaking that is a defect, not a breaking change
to announce and ship — there is no version bump that makes writing an
incompatible header acceptable.

## Component boundaries

The [interop matrix](engineering.md#the-interop-matrix) is measured against cryptsetup 2.7.5 and the Linux kernel in
the integration container ([test strategy](engineering.md#test-strategy)).
The cryptsetup/systemd two-way tests (`compatmatrix`, `fipsimport`,
`sha1af`, `headercopies`) live in `test/integration/interop/`: cryptsetup and
systemd are the real peer, so these tests drive the real binaries in both
directions. Four white-box integration files stay in `pkg/luks2` instead,
under `//go:build integration`: `canonicalconformance_integration_test.go`,
`lockcompat_integration_test.go`, `lockwait_integration_test.go` and
`pinnedpaths_integration_test.go`. Each builds a `Volume` with a
`volumeSys` it overrides, as an in-package unit test does, because each
needs a seam the public API must never expose:

- `cryptoRand`, `newUUID` and `digestIterationsFor` (determinism: a
  byte-for-byte comparison against a cryptsetup-written golden image);
- `calibratedCountFloor` (a cheap KDF cost, so a real-cryptsetup lock test
  runs in budget);
- `lockHeld` (a lock already held, to drive the wait);
- `openFile` (through `relinkAfterFirstOpen`, re-pointing a symlink the
  instant it is first opened, to prove a writer stays on the descriptor it
  locked).

Exporting any of them, even to the module's own `test/` tree, would make a
security- or determinism-relevant seam of a Layer-0 library reachable from
outside the package. A file qualifies for this exception only when both
hold: its hook is a correctness- or security-relevant seam of `pkg/luks2`,
and no exported API could carry it without exposing it to every caller.

## Stricter than cryptsetup

Each row is a refusal or an omission that leaves the volume as cryptsetup
wrote it; none stops a cryptsetup volume from opening.

| go-luks2 | cryptsetup | Why |
|---|---|---|
| A lock wait ends after 30 s (`DefaultLockWait`; `WithLockWait` sets another bound) with `ErrLockContended` | waits forever | a wait nothing will end is a hang |
| A new passphrase is 8–512 bytes (`MinPassphraseLength`, `MaxPassphraseLength`; outside them, `ErrInvalidCredential`); an existing one may be 1 byte to 8 MiB | enrolls any length, an 8 MiB key file included | a new credential is chosen now and can meet a floor |
| Persistent `allow-discards` is not passed to dm-crypt; the performance flags are | passes all of them | the header is untrusted, and discards disclose which blocks are free to anyone who can read the medium; the data is the same either way |
| Activation refused for a detached header | activates with `--header` | activation (`Target`) maps the device the header was read from and takes no second device; the keyslots are still managed |
| Keyslots tried only if bound to the data segment, never by priority | priority order | an unbound key maps garbage |
| Headers that fail cryptsetup's structural rules, or carry an ambiguous JSON member, are refused | refuses most of the same | see [header/architecture.md](../header/architecture.md#untrusted-headers) |
| SHA-1 and Argon2 refused in FIPS 140-3 mode | no FIPS mode of its own | see [fips/architecture.md](../fips/architecture.md) |
| A header with more than 32 keyslots or 32 digests is refused on read; keyslot ids above 31 are never tried | reads them (measured: 200 keyslots, 40 digests) and tries every keyslot | cryptsetup writes no such header, and each entry is derivation work a crafted header adds to every unlock |
| One operation's key derivation is capped at the most a cryptsetup header can ask for (`ErrInvalidHeader`, before any derivation) | no aggregate cap | a crafted header could otherwise multiply the per-derivation ceiling; `TestCompatCryptsetupsMaximumKeyslotsAndCostsAreNotRefused`, `TestCompatAmplifiedDigestsAreRefusedByBothTools` |
| Per derivation: PBKDF2 at most 100,000,000 iterations, Argon2 at most 10,000 passes | up to 2^32 − 1 | see [header/architecture.md](../header/architecture.md#untrusted-headers) |

Reads (`(*Volume).Header`, `SecondaryHeader`, `Unlock`) take the lock
shared, as cryptsetup's do, so a read waits behind a write rather than
racing it; only the 30 s bound differs.

## What this feature deliberately does not do

No attempt to match cryptsetup's own bugs or undocumented leniency beyond
what the [interop matrix](engineering.md#the-interop-matrix) measures; a divergence not in that matrix is a defect
to investigate, not an assumed-fine gap.
