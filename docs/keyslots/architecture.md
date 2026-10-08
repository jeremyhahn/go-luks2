# Keyslots — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

A LUKS2 volume has up to 32 keyslots (0–31). Each normally wraps the same
volume key under a different credential, so credentials can be added and
revoked without re-encrypting data. A header can also carry unbound keys whose
digest names no segment; unlock never maps one. An unbound keyslot never
counts as the last keyslot, and its credential cannot authorize adding a key,
killing a slot, testing a key or verifying a recovery key.

This folder covers keyslot structure, unlock order, cost inheritance and
removal. The credential that fills a keyslot is covered per kind: a plain
passphrase here, a generated credential in [recovery-keys](../recovery-keys/architecture.md),
and a helper- or hardware-backed one in [tokens](../tokens/architecture.md).
AES-XTS/CBC encryption of the keyslot area and the anti-forensic split are
[volumes/architecture.md#kernel-keyring](../volumes/architecture.md)'s sibling
topic, [volumes/encryption](../volumes/engineering.md); the header's byte
layout is [header](../header/architecture.md).

## The problem and the shape chosen

A credential should be revocable without re-encrypting the data it protects,
and more than one credential should be able to open the same volume. LUKS2's
answer — up to 32 independent wrappings of one volume key, each under its own
KDF cost and credential — is adopted unchanged; this library does not
reinvent the on-disk shape, only decides how strictly it is validated before
any passphrase is checked (see "Untrusted keyslots", below) and how costs are
chosen when a caller does not set one (see
[engineering.md](engineering.md#cost-inheritance)).

## Component boundaries

Keyslot logic lives inside `pkg/luks2` (`keyslot.go`, `keyslot_v2.go`,
`keyslotscreen.go`, `keyslotdevice.go`). The KDF
derivation itself (PBKDF2/Argon2, calibration, cost floors) is
`internal/kdf` (H4, DECISIONS.md); the anti-forensic split is `internal/af`
(H3c) and the area cipher is `internal/areacipher` (H3d). `pkg/luks2` owns
the keyslot *object* (which stripes, which area, which KDF it names) and the
policy around it (cost inheritance, removal guards).

The keyslot is a value the caller reads (`KeyslotInfo`, via
`(*Header).Keyslots()`) and a params struct it writes (`KeyslotParams{Slot,
Priority, KDF}`, via `(*Volume).AddKeyslot`/`ChangeKeyslot`); see
[engineering.md](engineering.md#exported-surface).

## Data flow: unlock order

`(*Volume).Unlock` scans: it tries only keyslots bound to the data segment,
every `prefer` keyslot before any `normal` one and each group in ascending slot
number, and never an `ignore` keyslot -- cryptsetup's order when no keyslot is
named. A header whose bound keyslots are all `ignore` gets `ErrNoKeyslots`
(cryptsetup's "no usable keyslot"). The key must verify against a digest of that
segment; a passphrase that opens only an unbound keyslot gets `ErrWrongKey`.
`UnlockKeyslot` does not scan: it tries exactly the slot it is given, and a
slot that does not exist or is not bound to the data segment is refused up
front with `ErrKeyslotNotFound`, before any derivation, whatever the
credential. A bound slot with the wrong passphrase gets `ErrWrongKey`.
`UnlockWithProvider` tries only the keyslots its provider's token names, as
cryptsetup tries a token named with `--token-id`: the `prefer` ones, then the
`normal` ones, then the `ignore` ones, each group in the token's order.
`AddKeyslot` and `ChangeKeyslot` take an already-recovered `Key` and unlock
nothing. **An `ignore` keyslot opens only when the caller names it:** through
`UnlockKeyslot`, or through a token passed to `UnlockWithProvider`, after the
token's other keyslots. `(*Header).Keyslots()` lists ascending slot numbers and reports each
slot's priority and KDF cost.

Keyslots this library creates carry no `priority` member unless the caller
asks for one, as cryptsetup writes them: `KeyslotParams.Priority`'s zero value
`PriorityDefault` means normal for a new keyslot and "unchanged" for
`ChangeKeyslot`, so an ignored keyslot exists only when a caller names
`PriorityIgnore`. An absent member reads as normal and a present one is kept
as read.

Steps, per keyslot tried:

1. Derive the wrapping key, `area.key_size` long, from the credential with the
   keyslot's KDF.
2. Read the area and decrypt it with the cipher `area.encryption` names.
3. Merge the keyslot's stripes into a candidate volume key.
4. Check the candidate against the digests that bind this keyslot.

The first keyslot whose candidate matches wins. A mismatch is reported as
`ErrWrongKey`; a keyslot that could not be tried at all is
reported separately (see [engineering.md](engineering.md#error-semantics)).

## Untrusted keyslots

Anyone with the disk can write the header, and keyslot fields decide how much
work an unlock does before any passphrase is checked. Keyslots are validated
one at a time, before each is used, so one damaged keyslot does not hide the
others and the header can still be inspected. A keyslot outside the bounds
below fails with an error matching `ErrKeyslotNotFound` before any derivation
or allocation.

| Field | Bound |
|---|---|
| `key_size` | declared 1–1024 bytes; only 16, 24, 32, 48 or 64 is tried (an AES data key) |
| `area.key_size` | 32, 48 or 64 for an XTS area, 16, 24 or 32 for CBC |
| `af.stripes` | 1–4000 |
| `area.size` | 1 byte – 128 MiB (cryptsetup's `LUKS2_MAX_KEYSLOTS_SIZE`) |
| `key_size × stripes` | at most `area.size` |
| PBKDF2 iterations | 1 – 100,000,000 |
| Argon2 time / memory / cpus | 1–10,000 / 8 KiB – 4 GiB / 1–255 |

The `area` must lie inside the keyslots area and clear of every data segment
on the same device (a detached header's data, at offset 0 of another device,
is not), or the keyslot is not opened and never wiped. Keyslots of a type
this library does not implement, such as `reencrypt`, are never tried, and
neither is a keyslot id outside 0–31.

The work of one operation is bounded as a whole, not just per keyslot
(`kdfbudget.go`):

- A header with more than 32 keyslots or 32 digests is refused on read
  (`ErrInvalidHeader`). cryptsetup reads such headers but never writes one.
- Before its first derivation, a keyslot scan prices every derivation it could
  make: each keyslot it would try and each digest attesting it. A total above
  the most expensive header cryptsetup can write fails with
  `ErrInvalidHeader`, with nothing derived.
- Every enclave is admitted against go-enclave's process `Allocator`; a scan
  whose largest keyslot needs more locked memory than that budget is refused
  up front with `ErrProtectedMemory`.

## What this feature deliberately does not do

No support for a keyslot type this library does not implement (`reencrypt`);
such a keyslot is listed but never tried, and the header is otherwise usable.
No unlock order of its own: a scan follows keyslot priority exactly as
cryptsetup's does ([unlock order](#data-flow-unlock-order),
[cryptsetup-interop](../cryptsetup-interop/architecture.md)).
