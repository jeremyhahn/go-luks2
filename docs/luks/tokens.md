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

For Trusted Platform Module:

```json
{
  "type": "systemd-tpm2",
  "keyslots": ["0"],
  "tpm2-pcrs": "7",
  "tpm2-bank": "sha256",
  "tpm2-primary-alg": "ecc",
  "tpm2-blob": "base64-encoded-sealed-key",
  "tpm2-policy-hash": "base64..."
}
```

| Field | Description |
|-------|-------------|
| tpm2-pcrs | PCR indices to bind to |
| tpm2-bank | PCR bank algorithm |
| tpm2-primary-alg | Primary key algorithm |
| tpm2-blob | Sealed key blob |
| tpm2-policy-hash | Policy session hash |

## go-luks2 Token API

### Import Token

```go
token := &luks2.Token{
    Type:     "systemd-fido2",
    Keyslots: []string{"0"},
    Data: map[string]interface{}{
        "fido2-credential": "base64...",
        "fido2-salt":       "base64...",
        "fido2-rp":         "io.systemd.cryptsetup",
    },
}

err := luks2.ImportToken(device, 0, token)
```

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

You can define custom token types:

```go
token := &luks2.Token{
    Type:     "my-custom-type",
    Keyslots: []string{"0"},
    Data: map[string]interface{}{
        "server": "https://keyserver.example.com",
        "key-id": "abc123",
    },
}

err := luks2.ImportToken(device, 0, token)
```

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

## Compatibility

go-luks2 tokens are compatible with:
- cryptsetup 2.4+
- systemd-cryptenroll
- clevis

Token format follows LUKS2 specification.
