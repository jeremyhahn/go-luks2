# External key providers

A credential that comes from something outside the process — a hardware
authenticator, an agent, a script — rather than from a human at a terminal.

```go
type KeyProvider interface {
    Passphrase(ctx context.Context) (*enclave.MemoryEnclave, error)
    Token() *Token
}
```

`Passphrase` runs whatever produces the credential and returns it in protected
memory, which is the caller's to `Destroy`. `Token` returns the header metadata
that records where it came from, or nil for an anonymous provider.

## One mechanism: run a command, take a line

`CommandKeyProvider` is the whole of it. The FIDO2 support is a *configuration*
of it rather than a second implementation, so a TPM helper, a network agent or a
smartcard script needs no new code in this package.

```go
type CommandKeyProvider struct {
    Path  string   // the helper, an absolute path -- never searched for on PATH
    Args  []string
    Stdin []byte
    Line  int      // 1-based line of stdout to take; 0 for all of it
    Meta  *Token
}
```

`Line > 0` takes that line **without its terminator**. `Line == 0` takes the
whole of stdout **verbatim**, newline included — the same rule as
`cryptsetup --key-file`, because a helper that emits a passphrase controls its
own bytes and trimming them silently is how a credential works one way and not
the other.

The helper's stdout is read directly into locked memory rather than through a
heap buffer, and its output is bounded at 64 KiB. Output that does not fit is
**refused**, not truncated: a truncated credential enrolls perfectly well and
opens nothing.

## Why helper binaries and not a linked library

FIDO2 interaction is delegated to `fido2-cred` and `fido2-assert` from libfido2,
not to a Go binding. A binding drags cgo into a package whose consumers
cross-compile it as pure Go, and it would put a USB transport, a PIN prompt and
device enumeration inside a library whose job is to write 4 KiB of JSON
correctly. **No new module dependency is added by any of this.**

## Enrolling

```go
slot, tokenID, err := luks2.EnrollKeyProvider(ctx, "/dev/sdb1", existing, provider, opts)
```

The keyslot is written first, because writing it is what produces the slot
number the token has to name — and that number is read from where the library
*chose* it, never inferred from the header afterwards.

If the token write then fails, **the keyslot is rolled back**. A keyslot with no
token is an orphan: it opens the volume, nothing on the device says what opens
it, and no operator inspecting the container later can tell it from a credential
still in use. When the rollback itself fails the caller gets an
`OrphanedKeyslotError` naming the slot, which at that point is the only record
of the credential that exists anywhere.

## Unlocking

```go
err := luks2.UnlockWithProvider(ctx, "/dev/sdb1", "backup", provider)

// or, from what the header already records
provider, err := luks2.ProviderFromToken(token, luks2.ExecConfig{Device: "/dev/hidraw0"})
```

`ctx` bounds the work. An authenticator waiting for a touch blocks until someone
touches it, and an unattended unlock needs that to end.

## FIDO2

```go
salt, _ := luks2.NewFIDO2Salt()

credID, _ := luks2.NewFIDO2Credential(ctx, cfg, luks2.FIDO2CredentialOptions{})

provider, _ := luks2.NewFIDO2KeyProvider(luks2.FIDO2Params{
    CredentialID: credID,
    Salt:         salt,
    UserPresence: true,
}, cfg)

slot, tokenID, err := luks2.EnrollKeyProvider(ctx, device, existing, provider, nil)
```

The token written is type `systemd-fido2`, with systemd's relying party
(`io.systemd.cryptsetup`), so a volume enrolled here is meant to be openable by
`systemd-cryptsetup`. None of the parameters are secret — all of them are in the
header in the clear. The security comes from the authenticator refusing to
derive the secret without the credential and the user's consent.

`-h` is passed at **creation** as well as at assertion. It is what gives the
credential an hmac-secret at all; a credential made without it can never produce
a secret, however the assertion is phrased, and the failure surfaces much later
as an unlock that yields nothing.

### What is enrolled is the base64 TEXT of the secret

systemd does not enroll the raw 32 bytes the authenticator derives. It enrolls
their **base64 text** as an ASCII passphrase. Enrolling the raw bytes instead
produces a keyslot `systemd-cryptsetup` can never open, and vice versa.

That systemd base64-encodes before enrolling is **verified** on systemd 255: the
string `Failed to base64 encode secret key: %m` is in the `systemd-cryptenroll`
binary, alongside the token type `systemd-fido2` and the field names this
package writes.

**Which** base64 was settled by measurement, not inference. Three YubiKeys were
enrolled into a real volume with `systemd-cryptenroll` (systemd 255, cryptsetup
2.7.0) and the six base64 members of the resulting tokens were counted:

| | count |
|---|---|
| standard-only characters (`+` `/`) | 4 |
| URL-safe-only characters (`-` `_`) | 0 |
| padding characters (`=`) | 9 |

The padding settles padding outright — the `Raw` encodings emit none, ever. The
alphabet count settles the alphabet: across ~250 characters of random material a
URL-safe encoder would be expected to emit several `-` or `_`, and it emitted
none. This was not decidable from the binary, which carries both tables adjacent
to one another.

What that proves is the encoding of the **token fields**. The
secret-as-passphrase goes through the same systemd helper, which makes it strong
evidence for that path rather than direct proof; settling it outright takes one
non-destructive assertion against a recorded credential and salt.

The whole of that uncertainty is one variable, `fido2SecretEncoding`, and one
function. Every path decodes the helper's output and **re-encodes** it through
that encoder rather than passing helper bytes through untouched, so if hardware
ever disproves the inference, one line changes and nothing else moves.

### The secret's line number

`fido2-assert -G -h` writes its fields one per line, and field 5 — the user id —
is emitted **only for a resident (discoverable) credential**. This package always
supplies a credential id and never passes `-r`, so the secret is on **line 5**,
not line 6.

CTAP2 leaves an authenticator some latitude about returning user information for
a single-entry allow list, which is exactly the latitude that would shift that
line. So the secret's **length** is checked as well as its position: the field
before it is a ~70-byte signature, and a decoded credential that is not 32 bytes
is refused. A wrong line would otherwise enroll cleanly and never open the
volume.

## Errors

| Sentinel | Meaning |
|---|---|
| `ErrKeyProvider` | Matches every failure in this area |
| `ErrNoKeyProvider` | No provider, or a token with nothing to build one from |
| `ErrHelperNotConfigured` | The provider names no command |
| `ErrHelperFailed` | The helper ran and exited non-zero — the authenticator refused, the touch timed out, the PIN was wrong |
| `ErrHelperOutput` | The helper **succeeded** and produced something unusable — too few lines, an empty credential, the wrong encoding |
| `ErrUnsupportedTokenType` | A token names a mechanism this package cannot drive |
| `ErrInvalidFIDO2Binding` | A binding is missing a field or carries one that does not decode |
| `ErrOrphanedKeyslot` | A credential is live in a keyslot that no token describes and that could not be removed |

`ErrHelperFailed` and `ErrHelperOutput` are deliberately separate: a helper that
exits 0 and prints the wrong thing is a protocol mismatch, and telling an
operator "the authenticator refused" would send them to look at the hardware.

`HelperError` carries the helper's own stderr, bounded at 4 KiB, because that is
where these tools say what actually happened.

## See Also

- [Tokens](tokens.md) — the header record a provider writes
- [Keyslots](keyslots.md) — what the credential goes into
