# Tokens — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-12 against a9c840c
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
Keyslots, Members}` — rather than modeling every vendor's fields: every member
it does not model (a FIDO2 token's credential, salt and requirement flags, a
TPM token's policy, any type a tool outside this library invents) is carried
in `Members` untouched, so writing a token back never drops what wrote it.

A key provider is this library's generic answer to "where does a credential
come from": one interface, `Passphrase`/`Token`, with the FIDO2 and
helper-command cases as its only implementations. This library has no TPM
code of its own; a consumer that needs to act on a TPM token implements
`KeyProvider` or unseals the key itself and calls `UnlockWithVolumeKey`
([volumes/engineering.md](../volumes/engineering.md#exported-surface)).

## Rejected alternatives

- **Typed vendor fields on `luks2.Token`.** Rejected: a generic `Token` with
  `Members` carries a type this library does not model, such as a
  systemd-tpm2 token, through a read-modify-write untouched; the
  systemd-fido2 members are written by `fido2Token` and read back by
  `fido2ParamsFromToken`, both in `pkg/keyprovider/fido2.go`, and nothing in
  `pkg/luks2` interprets them.
- **Key-provider implementations inside `pkg/luks2`.** Rejected: a separate
  `pkg/keyprovider` is the only way to keep `pkg/luks2` exec-free (it imports
  neither `os/exec` nor `internal/command`), and the interface it implements,
  `luks2.KeyProvider`, is defined at the consumer.
- **Checking a helper by path and executing the path afterwards.** Rejected:
  the path check judged only the directories left after symlinks were
  resolved, and `exec` reopened the path, so the file that ran need not be the
  file checked. The helper runs from the descriptor its checks were made on:
  `internal/command`'s `Open` (`open_linux.go`) checks the descriptor it
  opened, and `command.go` hands that descriptor to the child as its first
  extra file and executes it through `/proc/self/fd/3`.
- **Refusing every symlink on a helper's path.** Rejected: merged `/usr`
  layouts, distribution tool links and helpers linked into `/opt` are
  symlinks, and the walk already judges every directory such a path passes
  through, which is what the refusal would have protected. `Open` follows a
  symlink only when the link itself is owned by root or the caller, and walks
  its target with the same checks.

## Component boundaries

Token read/write (`token.go`; `Enroll` and `UnlockWithProvider` in
`provider.go`) lives in `pkg/luks2`.
Key-provider implementations (`Command`, FIDO2) live in `pkg/keyprovider`,
its own public package, which keeps `pkg/luks2` exec-free, implementing `luks2.KeyProvider`, defined at the consumer
(`pkg/luks2`) rather than at the implementer. `luks2.Token` stays generic
(`Type`, `Keyslots`, `Members map[string]json.RawMessage`); the FIDO2-specific
members are interpreted by `pkg/keyprovider` alone. FIDO2 runs `fido2-cred`
and `fido2-assert` from libfido2 as external helpers, from absolute paths
(`/usr/bin/fido2-cred` and `/usr/bin/fido2-assert` unless
`WithFIDO2Tools` names others), never looked up on `PATH`. A helper, like any
`Command`, must pass the trusted-executable checks every system tool does
(`internal/command`'s `Open`): a regular executable file owned by root or the
caller, not group- or world-writable, reached only through directories owned
the same way or sticky and through symlinks owned the same way, each judged
by the descriptor the walk opened rather than by name. One that fails is
refused with `ErrHelperFailed` and never run, and one that passes runs from
that same descriptor, so a path swapped after the check cannot substitute
another file. It runs
with the same fixed minimal environment every exec'd command gets
([volumes/architecture.md](../volumes/architecture.md#device-layer)); it does
not link a cgo binding, keeping the package pure Go.

## Data flow

**Enroll** (`(*Volume).Enroll`): choose a free token slot, write the keyslot, then a
token naming the slot it was given, all under one device lock, so two
enrollments at once cannot pick the same token slot. If the token write fails
the keyslot is removed, because a keyslot that nothing describes cannot be
told apart from a forgotten credential. If that removal also fails, the
error is an `OrphanedKeyslotError` naming the slot. A provider whose token
has no type is anonymous: Enroll writes the keyslot only and reports token
`-1`.

**Unlock with a provider** (`(*Volume).UnlockWithProvider` plus
`dmcrypt.Activate`): only the keyslots the provider's token names are tried,
by priority as cryptsetup tries a token named with `--token-id` (`prefer`,
then `normal`, then `ignore`, each in the token's order;
[keyslots](../keyslots/architecture.md#data-flow-unlock-order)). `ctx` bounds
the helper. An authenticator waiting for a
touch blocks until someone touches it; an unattended unlock needs a deadline.
The read of the helper's output ends with `ctx` even if a process the helper
started still holds its stdout; if the helper exits while such a process
keeps the pipe open, the read is cut off after a short grace period with
`ErrHelperOutput`.

**Rebuilding a provider from a token already on disk**
(`keyprovider.FromToken`): reads a `systemd-fido2` token's members back into a
provider that can be used for `(*Volume).UnlockWithProvider` without the
caller having kept its own configuration around. Any other token type is
refused with `ErrUnsupportedToken`.

## What this feature deliberately does not do

No TPM code: a TPM-backed token is read and round-tripped like any other
unmodeled token, but nothing here unseals a TPM-sealed key. No binding to a
specific FIDO2 library beyond `fido2-cred`/`fido2-assert`.
