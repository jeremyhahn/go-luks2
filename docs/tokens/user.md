# Tokens — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

Prerequisites: an existing LUKS2 volume ([volumes/user.md](../volumes/user.md)).
Reading and editing tokens on a file you own needs no root.

## See what opens a volume, beyond plain passphrases

```bash
sudo luks2 token list /srv/data.luks
```

Each row names a keyslot's credential source (a recovery key, a FIDO2
authenticator, a TPM policy written by another tool). This does not reveal
any secret: tokens hold no key material.

## Back up and restore a token

```bash
sudo luks2 token export /dev/sdb1 0 --file token0.json
# ... later, or on another header ...
sudo luks2 token import /dev/sdb1 0 --file token0.json
```

## Enroll a FIDO2 authenticator

```go
v, _ := luks2.Open(ctx, device)
defer v.Close()
key, _ := v.Unlock(ctx, existingPassphrase) // existingPassphrase is a *enclave.MemoryEnclave
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

There is no CLI verb for FIDO2 enrollment today; it is a library-only call
(`go doc github.com/jeremyhahn/go-luks2/pkg/keyprovider NewFIDO2`).

## Troubleshooting

| Symptom | Likely cause | Next step |
|---|---|---|
| `token remove` ran but the volume still opens with the old credential | `remove` deletes metadata only, never a keyslot | Use [`killslot`](../keyslots/cli.md#removekey-and-killslot) to revoke the credential itself |
| A FIDO2 unlock fails with a helper error | Wrong PIN, timed out waiting for touch, or the device is not the one named by `keyprovider.WithDevice` | Check `HelperError`'s captured stderr |
| `token import` refuses the JSON | A keyslot number in `keyslots` does not exist on this header, or is written with leading zeros (`"01"`) | Use the canonical id (`"1"`) and confirm the keyslot exists first with [keyslots](../keyslots/cli.md#keyslots) |
