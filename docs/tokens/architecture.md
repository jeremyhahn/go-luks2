# Tokens — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

A token is a JSON object in the header that records what opens a keyslot: a
FIDO2 authenticator, a TPM, a recovery key. It holds no key material and is
stored in the clear. A header has token slots 0–31, separate from keyslots.
This folder covers token structure and the `KeyProvider` interface that
produces a credential from outside the process (a helper program, FIDO2).
Recovery-key tokens are a type of token but are documented with the
credential they describe: [recovery-keys](../recovery-keys/architecture.md).

```json
{ "type": "systemd-fido2", "keyslots": ["1"], "fido2-credential": "...", ... }
```

Every token has `type` and `keyslots`. Removing a keyslot removes its number
from every token's `keyslots`; the token itself stays
([keyslots/engineering.md](../keyslots/engineering.md#persistence)). Removing
a token revokes nothing: the keyslot still opens the volume.

## The problem and the shape chosen

A keyslot wraps a credential; it does not say where that credential comes
from or how to ask for it again. A token is the header's answer: metadata a
tool can read to reconstruct the prompt (a FIDO2 relying party, a TPM PCR
policy, a helper command) without that metadata being guessable from the
keyslot itself. go-luks2 keeps the type genuinely generic — `Token{Type,
Keyslots, Members}` — rather than modeling every vendor's fields, because the
FIPS-mode exemption for FIDO2 flags and TPM policy would otherwise have to be
re-derived for every new token type a tool outside this library invents.

A key provider is this library's generic answer to "where does a credential
come from": one interface, `Passphrase`/`Token`, with the FIDO2 and
helper-command cases as its only implementations. This library has no TPM
code of its own; a consumer that needs to act on a TPM token implements
`KeyProvider` or unseals the key itself and calls `UnlockWithVolumeKey`
([volumes/engineering.md](../volumes/engineering.md#exported-surface)).

## Component boundaries

Token read/write (`token.go`, `token_v2.go`) lives in `pkg/luks2`.
Key-provider implementations (`Command`, FIDO2) live in `pkg/keyprovider`,
its own public package — "the only way to keep `pkg/luks2` exec-free"
(DESIGN.md §A.4) — implementing `luks2.KeyProvider`, defined at the consumer
(`pkg/luks2`) rather than at the implementer. `luks2.Token` stays generic
(`Type`, `Keyslots`, `Members map[string]json.RawMessage`); the FIDO2-specific
members are interpreted by `pkg/keyprovider` alone. FIDO2 runs `fido2-cred`
and `fido2-assert` from libfido2 as external helpers, through the same
trusted-tool resolution every exec'd command uses
([volumes/architecture.md](../volumes/architecture.md#device-layer)); it does
not link a cgo binding, keeping the package pure Go.

## Data flow

**Enroll** (`(*Volume).Enroll`): choose a free token slot, write the keyslot, then a
token naming the slot it was given, all under one device lock, so two
enrollments at once cannot pick the same token slot. If the token write fails
the keyslot is removed, because a keyslot that nothing describes cannot be
told apart from a forgotten credential. If that removal also fails, the
error is an `OrphanedKeyslotError` naming the slot.

**Unlock with a provider** (`(*Volume).UnlockWithProvider` plus
`dmcrypt.Activate`): `ctx` bounds the helper. An authenticator waiting for a
touch blocks until someone touches it; an unattended unlock needs a deadline.
The read of the helper's output ends with `ctx` even if a process the helper
started still holds its stdout; if the helper exits while such a process
keeps the pipe open, the read is cut off after a short grace period with
`ErrHelperOutput`.

**Rebuilding a provider from a token already on disk**
(`keyprovider.FromToken`): reads the token's members back into a provider
that can be used for `(*Volume).UnlockWithProvider` without the caller having
kept its own configuration around.

## What this feature deliberately does not do

No TPM code: a TPM-backed token is read and round-tripped like any other
unmodeled token, but nothing here unseals a TPM-sealed key. No binding to a
specific FIDO2 library beyond `fido2-cred`/`fido2-assert`.
