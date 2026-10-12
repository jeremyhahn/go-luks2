# Tokens — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-12 against a9c840c
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

There is no CLI verb for FIDO2 enrollment: it is done by a program built on
the library, which creates a credential on the authenticator, adds a keyslot
it opens, and records a `systemd-fido2` token naming that keyslot
([api.md](api.md#enroll-a-fido2-authenticator) shows the calls). The token
uses the relying party `io.systemd.cryptsetup`, so `systemd-cryptsetup` can
open the volume with the same authenticator. Afterwards `luks2 token list`
shows the new token.

## Troubleshooting

| Symptom | Likely cause | Next step |
|---|---|---|
| `token remove` ran but the volume still opens with the old credential | `remove` deletes metadata only, never a keyslot | Use [`killslot`](../keyslots/cli.md#removekey-and-killslot) to revoke the credential itself |
| A FIDO2 unlock fails with a helper error | Wrong PIN, timed out waiting for touch, or the device is not the one the unlocking program named | Read the helper's own message, which the error carries |
| `token import` refuses the JSON | A keyslot number in `keyslots` does not exist on this header, the token has no `type`, or the file is not a JSON token object | Confirm the keyslot exists first with [keyslots](../keyslots/cli.md#keyslots) (`"01"` is read as keyslot 1 and written back as `"1"`) |
