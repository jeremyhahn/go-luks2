# Tokens

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

A token is a JSON object in the header that records what opens a keyslot: a
FIDO2 authenticator, a TPM, a recovery key. It holds no key material and is
stored in the clear. A header has token slots 0–31, separate from keyslots.

```json
{ "type": "systemd-fido2", "keyslots": ["1"], "fido2-credential": "...", ... }
```

Every token has `type` and `keyslots`. Removing a keyslot removes its number
from every token's `keyslots`; the token itself stays. Removing a token revokes
nothing: the keyslot still opens the volume.

## Types

| Type | Written by | Members modeled in `Token` |
|---|---|---|
| `systemd-recovery` | `AddRecoveryKey` | `type`, `keyslots` only, as `systemd-cryptenroll --recovery-key` writes it |
| `systemd-fido2` | `EnrollKeyProvider` with a FIDO2 provider | `fido2-credential`, `fido2-salt`, `fido2-rp`, `fido2-clientPin-required`, `fido2-up-required`, `fido2-uv-required` |
| anything else (`systemd-tpm2`, vendor types) | other tools, or `ImportTokenJSON` | `type`, `keyslots` |

Members `Token` does not model are kept through every header rewrite (see
[header.md](header.md#encoding)), so a `systemd-tpm2` token written by
`systemd-cryptenroll` survives an unrelated `AddKey`. `GetToken` returns them
and `ExportToken` includes them.

This library has no TPM code. A consumer that needs to act on a TPM token
implements [`KeyProvider`](keyprovider.md) or unseals the key itself and calls
`UnlockWithVolumeKey`.

The three FIDO2 requirement flags are `*bool` because systemd writes `false`
deliberately and `omitempty` on a plain `bool` would drop it.

## API

```go
up, pin := true, false
err := luks2.ImportToken(device, 0, &luks2.Token{
	Type:                   luks2.TokenTypeSystemdFIDO2,
	Keyslots:               []string{"1"},
	FIDO2Credential:        "...",
	FIDO2Salt:              "...",
	FIDO2RP:                "io.systemd.cryptsetup",
	FIDO2UPRequired:        &up,
	FIDO2ClientPinRequired: &pin,
})

// A type Token does not model: import the JSON.
err = luks2.ImportTokenJSON(device, 1, []byte(`{"type":"my-agent","keyslots":["2"],"key-id":"abc123"}`))

tokens, err := luks2.ListTokens(device) // map[int]*luks2.Token
token, err := luks2.GetToken(device, 0) // ErrTokenNotFound if absent
raw, err := luks2.ExportToken(device, 0)
id, err := luks2.FindFreeTokenSlot(device) // ErrNoFreeTokenSlot when full
err = luks2.RemoveToken(device, 0)
```

`TokenExists` and `CountTokens` return a bool and a count. A token key that no
LUKS2 implementation can address, such as `"01"` or `"40"`, is not listed or
counted.
