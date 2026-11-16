# Tokens — API

> **Status: NORMATIVE** · Last verified: 2026-10-12 against a9c840c
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is an embedded Go
library; it has no REST, gRPC, QUIC, MCP or Unix-socket transport.

| Capability | Embedded (Go call) |
|---|---|
| List / read tokens | `(*Volume).Header(ctx) (*Header, error)`, then `(*Header).Tokens() map[int]Token` |
| Write / replace / remove a token | `(*Volume).AddToken`, `SetToken`, `RemoveToken` |
| Enroll a `KeyProvider`-backed credential | `(*Volume).Enroll(ctx, key, provider, KeyslotParams) (Enrollment, error)` |
| Unlock through a `KeyProvider` | `(*Volume).UnlockWithProvider(ctx, provider) (*Key, error)`, then `dmcrypt.Activate` |
| Build a provider | `keyprovider.NewCommand`, `keyprovider.NewFIDO2` |
| Rebuild a provider from a stored token | `keyprovider.FromToken(token, opts...)` |
| Token model | `luks2.Token` (`MarshalJSON`, `UnmarshalJSON`), `luks2.MaxTokens`, `luks2.TokenTypeRecovery`, `luks2.LegacyToken`, `luks2.KeyProvider`, `luks2.Enrollment` |
| Token errors (`pkg/luks2`) | `ErrTokenNotFound`, `ErrNoSpace`, `ErrKeyProvider`, `ErrOrphanedKeyslot`, `*OrphanedKeyslotError`, `ErrInvalidArgument`, `ErrKeyslotNotFound` |
| Command provider | `keyprovider.Command` (`Passphrase`, `Token`), `CommandOption`, `WithArgs`, `WithStdin`, `WithLine`, `WithEnv`, `WithToken` |
| FIDO2 provider | `keyprovider.FIDO2` (`Passphrase`, `Token`), `FIDO2Params`, `FIDO2Option`, `WithDevice`, `WithFIDO2Tools`, `FIDO2CredentialParams`, `NewFIDO2Credential`, `NewFIDO2Salt`, `TokenTypeFIDO2`, `DefaultRelyingParty`, `SaltLength`, `SecretLength` |
| Provider errors (`pkg/keyprovider`) | `ErrInvalidArgument`, `ErrHelperFailed`, `ErrHelperOutput`, `ErrNoDevice`, `ErrInvalidBinding`, `ErrUnsupportedToken`, `*HelperError` (`Unwrap`), `Error` |

## Enroll a FIDO2 authenticator

FIDO2 enrollment has no CLI verb; it is these library calls. Unlock with an
existing credential, create a credential and a salt on the authenticator,
then enroll a provider built from them. The process must have called
`enclave.HardenProcess` first ([key custody](../volumes/engineering.md#key-custody-detail)):

```go
v, _ := luks2.Open(ctx, device)
defer v.Close()
key, _ := v.Unlock(ctx, existingPassphrase) // existingPassphrase is an enclave.ByteAccess
defer key.Destroy()

salt, _ := keyprovider.NewFIDO2Salt()
credID, _ := keyprovider.NewFIDO2Credential(ctx, keyprovider.FIDO2CredentialParams{
	RelyingParty: keyprovider.DefaultRelyingParty,
}, keyprovider.WithDevice("/dev/hidraw0"))
provider, _ := keyprovider.NewFIDO2(keyprovider.FIDO2Params{
	CredentialID: credID, Salt: salt, UserPresence: true,
}, keyprovider.WithDevice("/dev/hidraw0"))
_, err := v.Enroll(ctx, key, provider, luks2.KeyslotParams{})
```

`keyprovider.WithDevice` names the authenticator and is required. A helper
failure is a `*keyprovider.HelperError`, whose `Stderr` carries the helper's
own message (wrong PIN, no touch, no such device). The full surface is in
[engineering.md](engineering.md#exported-surface).

No request/response schema, status code mapping or `scp` permission applies.
See [volumes/api.md](../volumes/api.md) for the general Layer 0 statement
this folder inherits.
