# LUKS2 Keyslots

Keyslots store encrypted copies of the master key, each protected by a different passphrase.

## Overview

LUKS2 supports up to 32 keyslots (0-31). Each keyslot:

- Contains an independently encrypted copy of the master key
- Uses its own passphrase and KDF parameters
- Can be added, changed, or removed without affecting others

## Keyslot Structure

```json
{
  "0": {
    "type": "luks2",
    "key_size": 64,
    "af": {
      "type": "luks1",
      "stripes": 4000,
      "hash": "sha256"
    },
    "area": {
      "type": "raw",
      "offset": "32768",
      "size": "258048",
      "encryption": "aes-xts-plain64",
      "key_size": 64
    },
    "kdf": {
      "type": "argon2id",
      "salt": "base64-encoded-salt",
      "time": 4,
      "memory": 1048576,
      "cpus": 4
    }
  }
}
```

## Fields

### type

Always `"luks2"` for standard keyslots.

### key_size

Master key size in bytes:
- 32 bytes (256 bits) for AES-128-XTS
- 64 bytes (512 bits) for AES-256-XTS (default)

### Argon2 cost floors: creating vs accepting

These are two different decisions and this library keeps them apart.

| | Bound | Applies to |
|---|---|---|
| **Create** | `MinArgon2MemoryKB` = 65536 | costs a *caller* supplies, on `Format` and `AddKey` |
| **Accept** | `minArgon2Memory` = 8 KiB | every read path, `RemoveKey`, `KillSlot` |

Refusing to *create* a weak keyslot is this library's judgement to make.
Refusing to *touch* a container someone else created is not: cryptsetup has no
such floor, a low-memory or embedded device has good reason to format below
64 MiB, and a library that will not rotate a credential on a container the
reference implementation considers valid has turned a hardening preference into
an interop failure.

**The invariant:** *every keyslot in a volume should be derivable by the hardware
that owns the volume.* The container's existing cost is the only evidence this
library has about that hardware, so `AddKey` and `ChangeKey` inherit it
**exactly**, without clamping — including below the create floor.

Clamping would break the invariant for exactly one slot, and buys nothing:

- **It can lock out the owning hardware, silently.** The machine adding a key
  need not be the machine using the volume. A clamp succeeds on a roomy
  workstation and writes a keyslot the 32 MiB target cannot derive at all —
  found later, by whoever needed that credential.
- **It adds no resistance.** A volume is only as strong as its *weakest*
  keyslot. Adding a 64 MiB slot beside four 32 MiB ones does not make the volume
  harder to attack; the attacker goes at a 32 MiB slot exactly as before.

The floor still binds wherever there is no evidence to defer to: costs the
caller supplies explicitly, and a container with no Argon2 cost to inherit
(which falls through to the package defaults, all above the floor).

### AddKey and ChangeKey inherit the volume's Argon2 cost

`AddKey` and `ChangeKey` take the Argon2 cost from the **container**, not from a
package default, when the caller does not choose one.

`AddKey`'s default used to be a hardcoded 1 GiB. On a volume deliberately
formatted at 512 MiB — chosen so it stays openable from a rescue USB or a small
recovery box — the first `AddKey` silently wrote a 1 GiB keyslot: inconsistent
with every neighbor, and precisely on the credential added for a recovery
scenario.

The inherited value is **reported**, not silent: `AddKeyOptions.InheritedArgon2Cost`
is written by `AddKey` and carries the container's cost when one was inherited,
nil otherwise. It is a field rather than a log line for the reason recorded on
`forgetKeyslotID` — a logger in a layer-0 primitive imposes a logging decision
on every embedding application.

Note that cryptsetup's `luksAddKey` does *not* inherit; it re-benchmarks, so the
new slot's cost is decided by whichever machine happens to be running. On a
machine with less memory than the last one that is the same mistake in the other
direction.

`ListKeyslots` reports each slot's KDF cost (`PBKDF2Iterations`, `Argon2Time`,
`Argon2MemoryKB`, `Argon2Parallel`). That is how a preserved below-floor cost is
observable: `ChangeKey` takes no options, so unlike `AddKey` it has no call-site
field to report through.

### priority

Optional; `0` ignore, `1` normal, `2` prefer. **The default is normal**, and the
larger value is the one tried *first*.

A normal keyslot carries **no priority member at all**. cryptsetup omits it on
`luksFormat` and `luksAddKey`, and `cryptsetup config --priority normal` deletes
it rather than writing `1`; this library does the same. Writing the default
states what every reader already assumes and breaks byte-identity for no
benefit.

The corollary matters when reading someone else's container: an **absent**
priority is *normal*, not *ignore*. Since essentially every cryptsetup-created
container has keyslots with no priority member, reading absence as the zero
value would report every one of them as a slot to skip.

A non-default priority is still written and still round-trips, including
`0` (ignore) — which is why the field is a pointer rather than a plain `int`.

### af (Anti-Forensic)

Protects against forensic key recovery:

| Field | Description |
|-------|-------------|
| type | Always "luks1" (LUKS1-compatible algorithm) |
| stripes | Number of stripes (default: 4000) |
| hash | Hash for diffusion function |

### area

Encrypted key material storage:

| Field | Description |
|-------|-------------|
| type | "raw" for standard storage |
| offset | Byte offset on device |
| size | Total size (key_size × stripes) |
| encryption | Cipher for key encryption |
| key_size | Size of encryption key |

### kdf

Key derivation function parameters. See [Key Derivation](kdf.md).

## Key Material Layout

Each keyslot's encrypted area contains:

```
┌─────────────────────────────────────────┐
│          Encrypted Key Material          │
├─────────────────────────────────────────┤
│  Stripe 0: 64 bytes (encrypted)         │
│  Stripe 1: 64 bytes (encrypted)         │
│  Stripe 2: 64 bytes (encrypted)         │
│  ...                                     │
│  Stripe 3999: 64 bytes (encrypted)      │
├─────────────────────────────────────────┤
│  Total: 64 × 4000 = 256,000 bytes       │
│  Padded to sector boundary              │
└─────────────────────────────────────────┘
```

## Keyslot Unlock Process

```
1. Read keyslot metadata from JSON
2. Get KDF parameters (salt, iterations, etc.)
3. Derive key from passphrase using KDF
4. Read encrypted key material from disk
5. Decrypt with derived key (AES-XTS)
6. Anti-forensic merge (combine 4000 stripes)
7. Verify against digest
8. If valid, use as master key
```

## Code Example

### Unlocking a Keyslot

```go
// Attempt unlock with passphrase
err := luks2.Unlock(device, passphrase, volumeName)
if err != nil {
    switch {
    case errors.Is(err, luks2.ErrNoKeyslots):
        // The header carries no keyslot this implementation can try. No
        // passphrase opens this container; do not ask the operator to retype.
    case errors.Is(err, luks2.ErrInvalidKeyslot):
        // A keyslot is damaged and could not evaluate the credential. The
        // passphrase may well be correct.
    case errors.Is(err, luks2.ErrInvalidHeader):
        // The header itself is malformed -- an unusable digest, or a keyslot
        // that no digest authenticates.
    case errors.Is(err, luks2.ErrMasterKeyVerification):
        // A keyslot judged the credential and the recovered key did not match
        // its digest. That is NOT the same as "the passphrase is wrong": a
        // wrong passphrase, the CORRECT passphrase over damaged key material,
        // and a semantically wrong digest are indistinguishable at that
        // comparison, so the library does not name a cause. See issue #68.
    }
}

// There is no ErrInvalidPassphrase to branch on. It was removed in #70: no path
// in this package could honestly return it, for the reason above, and a
// sentinel whose name is what everyone reaches for at that spot is a trap
// rather than a vocabulary.
```

### Checking Active Keyslots

```go
info, err := luks2.GetVolumeInfo(device)
if err != nil {
    return err
}

fmt.Printf("Active keyslots: %v\n", info.ActiveKeyslots)
// Output: Active keyslots: [0 1 3]
```

## Multiple Keyslots

### Use Cases

1. **Multiple Users**: Different passphrase per user
2. **Recovery Key**: Separate recovery passphrase
3. **Automation**: Keyfile in addition to passphrase
4. **Key Rotation**: Add new key, then remove old

### Adding a Keyslot

```go
// Add a new keyslot (requires existing passphrase)
slot := 1
err := luks2.AddKey(device, existingPass, newPass, &luks2.AddKeyOptions{
    Keyslot: &slot, // *int; nil auto-selects the first free slot
})
```

### Removing a Keyslot

```go
// Remove keyslot (wipes encrypted key material)
err := luks2.WipeKeyslot(device, 1)
```

## Security Considerations

### Keyslot Independence

- Each keyslot is cryptographically independent
- Compromising one passphrase doesn't reveal others
- Master key is the same, but protected differently

### Keyslot Wiping

Wiping a keyslot:
1. Overwrites the encrypted key area **with CSPRNG data**
2. Removes JSON metadata
3. Makes that passphrase unusable
4. Does not affect other keyslots

### Unused keyslot space is random, not zero

`Format` fills the entire keyslots area with CSPRNG data — the tail of keyslot
0's declared area and the ~15.7 MiB no keyslot occupies yet — and a destroyed
keyslot's area is overwritten with random rather than zeroed.

This is an **indistinguishability** property, not a secrecy one. Encrypted
AF-split key material is indistinguishable from random; a zeroed range is
distinguishable from all of it at a glance. Zeroes therefore publish the
container's key-management history — how many credentials exist, where they sit,
and which slots were used and later destroyed — to anyone holding the drive,
without breaking any encryption. cryptsetup fills both ranges for the same
reason.

It costs about 20 ms on a ~375 ms format (measured over 20 runs, 64 MiB image),
and the container is no longer sparse: 16 MiB is actually allocated.

`WipeKeyslot` still zeroes. It is an explicit operator command with its own
contract, not part of a key removal.

### Attack Resistance

- Strong KDF prevents brute-force attacks
- Anti-forensic split prevents partial recovery
- Multiple keyslots don't weaken security
