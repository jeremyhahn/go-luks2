# Tokens — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

## Exported surface

### `*Volume` and `pkg/keyprovider`

```go
const MaxTokens = 32
const TokenTypeRecovery = "systemd-recovery"
type Token struct { Type string; Keyslots []int; Members map[string]json.RawMessage }
func (v *Volume) AddToken(ctx context.Context, t Token) (int, error)
func (v *Volume) SetToken(ctx context.Context, id int, t Token) error
func (v *Volume) RemoveToken(ctx context.Context, id int) error
type KeyProvider interface {
	Passphrase(ctx context.Context) (*enclave.MemoryEnclave, error)
	Token() Token
}
type Enrollment struct { Keyslot KeyslotInfo; Token int }
func (v *Volume) Enroll(ctx context.Context, key *Key, p KeyProvider, kp KeyslotParams) (Enrollment, error)
func (v *Volume) UnlockWithProvider(ctx context.Context, p KeyProvider) (*Key, error)

// pkg/keyprovider
const TokenTypeFIDO2 = "systemd-fido2"
const DefaultRelyingParty = "io.systemd.cryptsetup"
type Command struct{ /* unexported */ }
func NewCommand(path string, opts ...CommandOption) (*Command, error)
type FIDO2 struct{ /* unexported */ }
func NewFIDO2(p FIDO2Params, opts ...FIDO2Option) (*FIDO2, error)
func FromToken(t luks2.Token, opts ...FIDO2Option) (luks2.KeyProvider, error)
func NewFIDO2Credential(ctx context.Context, p FIDO2CredentialParams, opts ...FIDO2Option) ([]byte, error)
func NewFIDO2Salt() ([]byte, error)
```

`(*Header).Tokens() map[int]Token` is the reader; `AddToken` picks the free
slot itself, `SetToken` writes a chosen id, `RemoveToken` deletes one. There
is no separate "does this id exist" or "how many tokens" call — read
`len((*Header).Tokens())` or check the map.

Build a `pkg/keyprovider.Command` with `NewCommand(path, ...CommandOption)`.
`Command.Token()` returns the `luks2.Token` to record, built from `WithToken`.
`pkg/keyprovider.FIDO2` is the FIDO2 provider. `luks2.LegacyToken`
(`= header.Token`) is the FIDO2-field-shaped on-disk struct the package keeps
for its own header codec; callers use `Token`.

## Invariants

- Every token has `type` and `keyslots`; `Keyslots` must name keyslots the
  header has, or the write fails with `ErrInvalidHeader` and nothing is
  written. They are written as canonical ids (`"1"`); token JSON read with
  `"01"` is read as keyslot 1. A token with no keyslots is
  written as `"keyslots":[]`.
- Members `Token` does not model survive a read-modify-write in every header
  rewrite ([header/engineering.md](../header/engineering.md#persistence)), so
  a `systemd-tpm2` token written by `systemd-cryptenroll` survives an
  unrelated `AddKeyslot`.
- `Enroll` is one
  operation under one device lock: the keyslot and its token are written
  together, and a token-write failure rolls the keyslot back (see
  [architecture.md](architecture.md#data-flow)).
- The three FIDO2 requirement flags are `*bool` on `LegacyToken` because
  systemd writes `false` deliberately and `omitempty` on a plain `bool`
  would drop it. `Token.Members` carries the same fields as raw JSON, so the
  same rule applies to whatever writes them (`pkg/keyprovider`).

## Token types

| Type | Written by | Members the library interprets |
|---|---|---|
| `systemd-recovery` | `AddRecoveryKey` | `type`, `keyslots` only, as `systemd-cryptenroll --recovery-key` writes it |
| `systemd-fido2` | `Enroll` with a `keyprovider.FIDO2` provider | `fido2-credential`, `fido2-salt`, `fido2-rp`, `fido2-clientPin-required`, `fido2-up-required`, `fido2-uv-required` |
| anything else (`systemd-tpm2`, vendor types) | other tools, or `AddToken` / `SetToken` | `type`, `keyslots` |

```go
// AddToken: the caller builds the FIDO2 members as raw JSON, as
// pkg/keyprovider.FIDO2.Token() does internally.
up, pin := true, false
members, _ := json.Marshal(struct {
	FIDO2Credential        string `json:"fido2-credential"`
	FIDO2Salt              string `json:"fido2-salt"`
	FIDO2RP                string `json:"fido2-rp"`
	FIDO2UPRequired        *bool  `json:"fido2-up-required"`
	FIDO2ClientPinRequired *bool  `json:"fido2-clientPin-required"`
}{"...", "...", "io.systemd.cryptsetup", &up, &pin})
var raw map[string]json.RawMessage
_ = json.Unmarshal(members, &raw)
id, err := v.AddToken(ctx, luks2.Token{
	Type:     keyprovider.TokenTypeFIDO2,
	Keyslots: []int{1},
	Members:  raw,
})
```

In practice a caller does not build FIDO2 members by hand: `pkg/keyprovider.FIDO2.Token()`
does it, and `(*Volume).Enroll` writes the keyslot and the token together
(see "FIDO2" below).

To check for a token, look up the id in `(*Header).Tokens()` or take its
`len`. A token key that no LUKS2 implementation can address, such as `"01"` or
`"40"`, is not listed or counted.

## `pkg/keyprovider.Command`

The one implementation runs a helper and takes a line of its output. FIDO2 is
a configuration of it, so a TPM helper or a network agent needs no new code
here.

```go
func NewCommand(path string, opts ...CommandOption) (*Command, error)
func WithArgs(args ...string) CommandOption
func WithStdin(b []byte) CommandOption
func WithLine(n int) CommandOption   // 1-based stdout line to take; 0/unset for all of stdout
func WithEnv(kv ...string) CommandOption
func WithToken(t luks2.Token) CommandOption // the token to record; absent means anonymous
```

The helper does not inherit the process environment: it gets
`PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin` and
`LC_ALL=C`, plus whatever `WithEnv` adds. `WithLine(n)`
with `n > 0` takes that line without its newline; with no `WithLine`, all of
stdout is taken verbatim, newline included, as `cryptsetup --key-file` would.
Stdout is read straight into locked memory; more than 64 KiB is refused, not
truncated. A helper that exits non-zero gives `ErrHelperFailed`; one that
exits 0 with unusable output gives `ErrHelperOutput`. `HelperError{Path,
ExitCode, Stderr, Kind, Err}` carries up to 4 KiB of the helper's stderr.

```go
cmd, err := keyprovider.NewCommand("/usr/local/bin/get-key", keyprovider.WithLine(1))

// existingKey came from an earlier v.Unlock(ctx, existingPass).
enrollment, err := v.Enroll(ctx, existingKey, cmd, luks2.KeyslotParams{})

// Later, unlock and activate using the provider instead of a passphrase.
key, err := v.UnlockWithProvider(ctx, cmd)
mapping, err := dmcrypt.Activate(ctx, v, key, "my-encrypted-disk")
```

## FIDO2

FIDO2 runs `fido2-cred` and `fido2-assert` from libfido2 rather than linking a
binding, which would bring cgo into a pure-Go package.

```go
salt, err := keyprovider.NewFIDO2Salt()
credID, err := keyprovider.NewFIDO2Credential(ctx, keyprovider.FIDO2CredentialParams{
	RelyingParty: keyprovider.DefaultRelyingParty,
}, keyprovider.WithDevice("/dev/hidraw0"))
fido2, err := keyprovider.NewFIDO2(keyprovider.FIDO2Params{
	CredentialID: credID,
	Salt:         salt,
	UserPresence: true,
}, keyprovider.WithDevice("/dev/hidraw0"))
enrollment, err := v.Enroll(ctx, key, fido2, luks2.KeyslotParams{})
```

The token is `systemd-fido2` with relying party `io.systemd.cryptsetup`, so
`systemd-cryptsetup` can open the volume. Like systemd, the library enrolls
the standard base64 text of the 32-byte hmac-secret as the passphrase, not
the raw bytes.

`WithDevice` is required (`ErrNoDevice` otherwise) and is passed after `--`.
The token records `fido2-up-required`, `fido2-clientPin-required` and
`fido2-uv-required`; `keyprovider.FromToken` reads all three back from a
token already on disk. An absent member reads as false.

Two details that would otherwise enroll a credential that never opens:

- `-h` is passed when the credential is created as well as when it is used;
  without it the credential has no hmac-secret.
- `fido2-assert -G -h` prints the secret on line 5 for a non-resident
  credential. The re-encoded secret must also be 44 base64 characters (the
  length for 32 bytes), which refuses most shifted lines.

## Error semantics

| Error | Meaning | Package |
|---|---|---|
| `ErrKeyProvider` | Matched by an `OrphanedKeyslotError`, alongside `ErrOrphanedKeyslot`. A provider's own failure is returned as the provider reported it (from `pkg/keyprovider`: the rows marked `keyprovider` below), not as `ErrKeyProvider` | `luks2` |
| `ErrInvalidArgument` | No provider, a provider whose token names no keyslot (`UnlockWithProvider`), a token with no type (`AddToken`, `SetToken`), or a token id outside 0–31 | `luks2` |
| `ErrKeyslotNotFound` | `UnlockWithProvider`: the token names a keyslot that does not exist or is not bound to the data segment | `luks2` |
| `ErrUnsupportedToken` | The token names a mechanism this provider cannot drive (`FromToken`) | `keyprovider` |
| `ErrOrphanedKeyslot` | A keyslot is live with no token and could not be removed | `luks2` |
| `ErrTokenNotFound` | `RemoveToken` found no token at that id (`SetToken` writes the id whether or not one is there) | `luks2` |
| `ErrNoSpace` | All 32 token slots are in use | `luks2` |
| `ErrInvalidArgument` | A helper path that is not absolute or not configured, a negative line number | `keyprovider` |
| `ErrHelperFailed` | The helper exited non-zero: refused, timed out, wrong PIN | `keyprovider` |
| `ErrHelperOutput` | The helper succeeded but its output is unusable | `keyprovider` |
| `ErrNoDevice` | A FIDO2 operation was given no device | `keyprovider` |
| `ErrInvalidBinding` | A FIDO2 binding is missing a field or does not decode | `keyprovider` |

## Persistence

Token JSON shape and its place in the header are
[header/engineering.md](../header/engineering.md#persistence). Unmodeled
members are kept exactly (including large integers and number spellings) in
every header rewrite.

## Test strategy

Covered by `pkg/luks2`'s unit suite (enroll/unlock round trips against fake
providers, orphaned-keyslot rollback), `pkg/keyprovider`'s (fake helpers,
FIDO2 secret encoding) and the
cryptsetup compatibility matrix's `token*` row
([cryptsetup-interop/engineering.md](../cryptsetup-interop/engineering.md)).

## Observability

No logging; every failure above is a typed, returned error.
