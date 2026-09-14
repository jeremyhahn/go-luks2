# LUKS2 Tokens

Tokens provide a mechanism for storing metadata about external key sources, such as hardware security devices.

## Overview

LUKS2 tokens are JSON objects stored in the header that describe how to obtain a passphrase or key from an external source:

- **FIDO2**: Hardware security keys (YubiKey, etc.)
- **TPM2**: Trusted Platform Module
- **Custom**: User-defined token types

## Token Structure

```json
{
  "tokens": {
    "0": {
      "type": "systemd-fido2",
      "keyslots": ["0"],
      "fido2-credential": "base64...",
      "fido2-salt": "base64...",
      "fido2-rp": "io.systemd.cryptsetup",
      "fido2-clientPin-required": false,
      "fido2-up-required": true
    }
  }
}
```

## Token Slots

LUKS2 supports up to 32 token slots (0-31), independent of keyslots.

### Token-to-Keyslot Mapping

Tokens reference keyslots they can unlock:

```json
{
  "keyslots": ["0", "1"]
}
```

This means the token can unlock keyslots 0 and 1.

## Supported Token Types

### FIDO2 Tokens

For hardware security keys:

```json
{
  "type": "systemd-fido2",
  "keyslots": ["0"],
  "fido2-credential": "base64-encoded-credential-id",
  "fido2-salt": "base64-encoded-salt",
  "fido2-rp": "io.systemd.cryptsetup",
  "fido2-clientPin-required": false,
  "fido2-up-required": true,
  "fido2-uv-required": false
}
```

| Field | Description |
|-------|-------------|
| fido2-credential | Credential ID from enrollment |
| fido2-salt | Salt for key derivation |
| fido2-rp | Relying party identifier |
| fido2-clientPin-required | Require PIN entry |
| fido2-up-required | Require user presence (touch) |
| fido2-uv-required | Require user verification |

### TPM2 Tokens

**go-luks2 models no TPM2 member, deliberately.** go-xkms owns all hardware and
cloud crypto — TPM2, PKCS#11, and the KMS backends — and this is a Layer 0
library that carries none of it.

A `systemd-tpm2` token is still handled correctly, because handling it does not
require understanding it. Every member this package does not model is carried
through a read-modify-write byte for byte, so a token written by
`systemd-cryptenroll` survives a header rewrite exactly as systemd wrote it:

```json
{
  "type": "systemd-tpm2",
  "keyslots": ["0"],
  "tpm2-blob": "base64-encoded-sealed-key",
  "tpm2-pcrs": [7],
  "tpm2-pcr-bank": "sha256",
  "tpm2-primary-alg": "ecc",
  "tpm2-policy-hash": "base64..."
}
```

Read it back with `GetToken` and the members are all there. Only `type` and
`keyslots` — which LUKS2 itself defines — are typed fields.

#### Supplying a TPM2-backed credential

A consumer that needs to *interpret* such a token implements `KeyProvider`:

```go
type KeyProvider interface {
	Passphrase(ctx context.Context) (*enclave.MemoryEnclave, error)
	Token() *Token
}
```

go-xkms supplies the unsealed credential and the token identifying it; go-luks2
enrolls the one and writes the other without interpreting either. That is the
injection seam, and it is the only place hardware-backed credentials enter this
library.

See [keyprovider.md](keyprovider.md).

## go-luks2 Token API

### Import Token

```go
clientPin, userPresence, userVerification := true, true, false

token := &luks2.Token{
    Type:                   luks2.TokenTypeSystemdFIDO2,
    Keyslots:               []string{"0"},
    FIDO2Credential:        "base64...",
    FIDO2Salt:              "base64...",
    FIDO2RP:                "io.systemd.cryptsetup",
    FIDO2ClientPinRequired: &clientPin,
    FIDO2UPRequired:        &userPresence,
    FIDO2UVRequired:        &userVerification,
}

err := luks2.ImportToken(device, 0, token)
```

The three requirement flags are `*bool` because `false` is a value systemd
writes deliberately, and a plain `bool` with `omitempty` cannot express it --
the member would simply vanish from the token.

### List Tokens

```go
tokens, err := luks2.ListTokens(device)
for id, token := range tokens {
    fmt.Printf("Token %d: %s\n", id, token.Type)
}
```

### Get Token

```go
token, err := luks2.GetToken(device, 0)
if err != nil {
    if errors.Is(err, luks2.ErrTokenNotFound) {
        // Token doesn't exist
    }
}
```

### Export Token

```go
jsonData, err := luks2.ExportToken(device, 0)
// Returns JSON representation
```

### Remove Token

```go
err := luks2.RemoveToken(device, 0)
```

### Find Free Slot

```go
slot, err := luks2.FindFreeTokenSlot(device)
// Returns first available slot (0-31)
```

### Count Tokens

```go
count, err := luks2.CountTokens(device)
fmt.Printf("Active tokens: %d\n", count)
```

## Custom Token Types

You can define custom token types. A token whose members `Token` does not model
is imported as JSON:

```go
tokenJSON := []byte(`{
    "type": "my-custom-type",
    "keyslots": ["0"],
    "server": "https://keyserver.example.com",
    "key-id": "abc123"
}`)

err := luks2.ImportTokenJSON(device, 0, tokenJSON)
```

## Unmodeled Members Are Preserved

Every header write re-serializes the whole metadata blob, so a token is
rewritten whenever a keyslot changes -- even though the operation has nothing
to do with it. Members that `Token` does not model are therefore carried
verbatim across a read-modify-write cycle rather than dropped.

This matters because token types are defined outside this library: systemd
adds members between releases, and a vendor may define a type of its own. A
`systemd-fido2` token enrolled by `systemd-cryptenroll` survives an
unrelated `AddKey` with all of its members intact, including any this library
has never heard of. Values are preserved byte for byte, so a 64-bit handle is
not rounded and a number written as `1e3` does not come back as `1000`.

The same applies to keyslots and to their nested `area`, `kdf` and `af`
objects. It does NOT yet apply to the `segments`, `digests` and `config`
objects, which are still closed.

## Token Workflow

### Enrollment

```
1. Authenticate with existing passphrase
2. Generate or obtain external credential
3. Derive key from credential
4. Add new keyslot with derived key
5. Store token metadata linking credential to keyslot
```

### Unlock

```
1. Read token metadata from header
2. Use token info to access external source
3. Obtain key/passphrase from external source
4. Unlock referenced keyslot
```

## Security Considerations

### Token Metadata

- Token data is stored in plaintext in the header
- Do not store sensitive data directly in tokens
- Tokens should only contain references/IDs

### Keyslot Binding

- Tokens should only reference valid keyslots
- Removing a keyslot should update/remove tokens

### External Dependencies

- Token unlock requires external device/service
- Have backup passphrase keyslot
- Test recovery procedures

## Recovery tokens

A recovery keyslot carries the token `systemd-cryptenroll --recovery-key`
writes, and it is the whole token:

```json
{
  "type": "systemd-recovery",
  "keyslots": ["1"]
}
```

There is no format member and no algorithm member, because there is nothing to
record: the credential is the printed text an operator is holding. The token's
job is to say that the slot is a recovery key rather than somebody's second
passphrase — a distinction that otherwise exists only in a filing cabinet, and
that decides whether the slot gets revoked.

`luks2 recovery add` writes it, and rolls the keyslot back if it cannot.

## See Also

- [External key providers](keyprovider.md) — enrolling and unlocking with the
  credential a token describes, and the FIDO2 helper protocol
- [luks2 token](../cli/token.md) — the command-line interface to these

## Compatibility

go-luks2 tokens are compatible with:
- cryptsetup 2.4+
- systemd-cryptenroll
- clevis

Token format follows LUKS2 specification.
