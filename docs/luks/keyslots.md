# Keyslots

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

A LUKS2 volume has up to 32 keyslots (0–31). Each normally wraps the same
volume key under a different credential, so credentials can be added and
revoked without re-encrypting data. A header can also carry unbound keys whose
digest names no segment; unlock tries bound keyslots first.

## Structure

| Member | Meaning |
|---|---|
| `type` | `luks2`. Other types (`reencrypt`) are listed but never tried. |
| `key_size` | Volume key length in bytes: 32, 48 or 64 for AES-XTS (this library formats 32 or 64). Fixed at format, so `AddKeyOptions` has no key-size option. |
| `af` | Anti-forensic split: `luks1`, 4000 stripes when written (1–4000 read), hash `sha256` or `sha512` (SHA-1 is read only). |
| `area` | Where the wrapped key lives: `offset`, `size` (at least `key_size × stripes`), `encryption` (`aes-xts-plain64`; `aes-xts-plain` is also read), `key_size`. |
| `kdf` | How the credential becomes the wrapping key; see [kdf.md](kdf.md). |
| `priority` | Optional: 0 ignore, 1 normal, 2 prefer. Absent means normal. |

A full example is in [header.md](header.md#json-metadata).

## Unlock order

`Unlock` tries keyslots bound to every data segment first, then the rest, each
group in ascending slot number. **`priority` is not read by any unlock path.**
`ListKeyslots` lists ascending slot numbers and reports each slot's priority
and KDF cost.

Keyslots this library creates carry no `priority` member, as cryptsetup
writes them; an absent member reads as normal and a present one is kept as
read.

## Unlock steps

1. Derive the wrapping key from the credential with the keyslot's KDF.
2. Read the area and decrypt it with AES-XTS.
3. Merge the 4000 stripes into a candidate volume key.
4. Check the candidate against the digests that bind this keyslot.

The first keyslot whose candidate matches wins. A mismatch is reported as
`ErrMasterKeyVerification`; a keyslot that could not be tried at all is
reported separately (see the [library guide](README.md#errors-to-branch-on)).

## Adding and changing

```go
slot, err := luks2.AddKey(device, existing, newPass, &luks2.AddKeyOptions{
	KDFType: "pbkdf2-sha512", // empty: DefaultKDFType()
})
err = luks2.ChangeKey(device, oldPass, newPass, slot)
```

`AddKey` returns the slot it wrote, chosen under the device lock;
`AddKeyOptions.Keyslot` asks for a specific one. Never infer the slot from the
header afterwards: slots need not be contiguous.

### Argon2 cost

When the caller sets no Argon2 cost, `AddKey` takes it from the volume's first
Argon2 keyslot, and `ChangeKey` keeps the cost of the slot it rewrites. Either
may be below the create floor. A volume formatted small to stay openable on
small hardware stays that way. `AddKey` reports an inherited cost in
`AddKeyOptions.InheritedArgon2Cost`.

| Bound | Value | Applies to |
|---|---|---|
| Create floor | `MinArgon2MemoryKB` = 65536 | Costs a caller passes to `Format` or `AddKey` |
| Accept floor | 8 KiB | Reading, inheriting, removing |

`ChangeKey` rewrites a SHA-1 keyslot as PBKDF2-SHA256 with a SHA-256 split; see
[FIPS.md](../FIPS.md#sha-1).

## Removing

| Call | Authenticates with | Area afterwards |
|---|---|---|
| `RemoveKey` | that slot's passphrase | random |
| `KillSlot` | any valid passphrase | random |
| `KillKeyslot` | nothing | random |
| `WipeKeyslot` | nothing | zeroes |

Every path refuses to remove the last keyslot that can open the volume
(`ErrLastKeyslot`). Removing a keyslot drops its number from every digest and
token; a token left naming no keyslot is kept.

`RemoveKey`, `KillSlot` and `KillKeyslot` fill the freed area with random bytes,
because encrypted key material looks random and zeroes would show which slots
were used. `WipeKeyslot` zeroes it.
