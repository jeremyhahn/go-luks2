# External key providers

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

A key provider supplies a credential from outside the process: a hardware
authenticator, an agent, a script.

```go
type KeyProvider interface {
	Passphrase(ctx context.Context) (*enclave.MemoryEnclave, error)
	Token() *Token
}
```

`Passphrase` returns the credential in locked memory; the caller destroys it.
`Token` returns the header token describing the credential, or nil.

## CommandKeyProvider

The one implementation runs a helper and takes a line of its output. FIDO2 is a
configuration of it, so a TPM helper or a network agent needs no new code here.

```go
type CommandKeyProvider struct {
	Path  string   // absolute; anything else is ErrHelperPathNotAbsolute
	Args  []string
	Stdin []byte
	Line  int      // 1-based stdout line to take; 0 for all of stdout
	Meta  *Token   // token to record, or nil
	Env   []string // extra NAME=value entries for the helper
}
```

- The helper does not inherit the process environment. It gets
  `PATH=/usr/sbin:/usr/bin:/sbin:/bin` plus `Env`.

- `Line > 0` takes that line without its newline. `Line == 0` takes all of
  stdout verbatim, newline included, as `cryptsetup --key-file` would.
- Stdout is read straight into locked memory. More than 64 KiB is refused, not
  truncated.
- A helper that exits non-zero gives `ErrHelperFailed`; one that exits 0 with
  unusable output gives `ErrHelperOutput`. `HelperError` carries up to 4 KiB of
  the helper's stderr.

## Enroll and unlock

```go
slot, tokenID, err := luks2.EnrollKeyProvider(ctx, "/dev/sdb1", existing, provider, nil)

err = luks2.UnlockWithProvider(ctx, "/dev/sdb1", "backup", provider)

// Or rebuild the provider from the token the header already holds.
provider, err = luks2.ProviderFromToken(token, luks2.ExecConfig{Device: "/dev/hidraw0"})
```

`EnrollKeyProvider` chooses a free token slot, writes the keyslot, then a token
naming the slot it was given, all under one device lock, so two enrollments at
once cannot pick the same token slot. If the token write fails the keyslot is removed, because a keyslot that
nothing describes cannot be told apart from a forgotten credential. If that
removal also fails, the error is an `OrphanedKeyslotError` naming the slot.

`ctx` bounds the helper. An authenticator waiting for a touch blocks until
someone touches it; an unattended unlock needs a deadline. The read of the
helper's output ends with `ctx` even if a process the helper started still
holds its stdout. If the helper exits while such a process keeps the pipe open,
the read is cut off after a short grace period with `ErrHelperOutput`.

## FIDO2

FIDO2 runs `fido2-cred` and `fido2-assert` from libfido2 rather than linking a
binding, which would bring cgo into a pure-Go package.

```go
salt, err := luks2.NewFIDO2Salt()
credID, err := luks2.NewFIDO2Credential(ctx, cfg, luks2.FIDO2CredentialOptions{})
provider, err := luks2.NewFIDO2KeyProvider(luks2.FIDO2Params{
	CredentialID: credID,
	Salt:         salt,
	UserPresence: true,
}, cfg)
slot, tokenID, err := luks2.EnrollKeyProvider(ctx, device, existing, provider, nil)
```

The token is `systemd-fido2` with relying party `io.systemd.cryptsetup`, so
`systemd-cryptsetup` can open the volume. Like systemd, the library enrolls the
standard base64 text of the 32-byte hmac-secret as the passphrase, not the raw
bytes. `fido2SecretEncoding` is the one place that choice is made.

`ExecConfig.Device` is required (`ErrNoFIDO2Device` otherwise) and is passed
after `--`. The token records `fido2-up-required`, `fido2-clientPin-required`
and `fido2-uv-required`, and `ProviderFromToken` reads all three back; an
absent member reads as false.

Two details that would otherwise enroll a credential that never opens:

- `-h` is passed when the credential is created as well as when it is used;
  without it the credential has no hmac-secret.
- `fido2-assert -G -h` prints the secret on line 5 for a non-resident
  credential. The re-encoded secret must also be 44 base64 characters (the
  length for 32 bytes), which refuses most shifted lines.

## Errors

| Error | Meaning |
|---|---|
| `ErrKeyProvider` | Matches every failure below |
| `ErrNoKeyProvider` | No provider, or a token with nothing to build one from |
| `ErrHelperNotConfigured` | The provider names no command |
| `ErrHelperPathNotAbsolute` | The helper path is relative or a bare name |
| `ErrNoFIDO2Device` | A FIDO2 operation was given no device |
| `ErrHelperFailed` | The helper exited non-zero: refused, timed out, wrong PIN |
| `ErrHelperOutput` | The helper succeeded but its output is unusable |
| `ErrUnsupportedTokenType` | `ProviderFromToken` was given a type it cannot drive |
| `ErrInvalidFIDO2Binding` | A FIDO2 binding is missing a field or does not decode |
| `ErrOrphanedKeyslot` | A keyslot is live with no token and could not be removed |
