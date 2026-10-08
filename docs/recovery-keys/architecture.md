# Recovery keys — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

A recovery key is a random credential in an ordinary keyslot, meant to be
written down and kept away from the volume. It is not a different on-disk
mechanism from a passphrase keyslot ([keyslots](../keyslots/architecture.md)):
it is the same keyslot shape, filled with a library-generated credential
instead of a caller-supplied one, plus a `systemd-recovery` token
([tokens](../tokens/architecture.md)) naming which slot it is.

## The problem and the shape chosen

A passphrase keyslot is only as strong as its KDF cost, because a human
passphrase has to be searched for offline. A recovery key has no such search:
it is drawn by the library's own CSPRNG, so the credential itself carries all
the entropy and the KDF only needs to be fast enough to open promptly. That is
why recovery keyslots get their own, lower iteration floor
([engineering.md](engineering.md#generated-credentials)) rather than reusing
the passphrase floor — the two credentials are defended by different things,
and one floor would either slow down recovery for no security reason or let a
weak human passphrase through.

The printed text, not the decoded bytes, is what the keyslot holds. This
means the same recovery key opens the volume through stock cryptsetup too
(`cryptsetup open <device> <name>`, pasted), because a keyslot credential is
just bytes to cryptsetup and the printed text is exactly those bytes.

## Component boundaries

Recovery-key rendering and parsing live in `internal/recoverykey` (H3e,
DECISIONS.md): `Format` (the enum), `Len`, `Render`, `Hash`, `Credential`,
`FirstLine` and `Decode` (the tolerant decode for pre-text-credential
volumes). `pkg/luks2` exports `RecoveryKeyFormat` (`uint8` enum,
`RecoveryDashed`/`RecoveryHex`/`RecoveryBase64`) over it, used by
`NewRecoveryKey`/`(*Volume).AddRecoveryKey`.

`internal/cli` (`recoveryfile.go`) does its own file reading and writing
against `(*RecoveryKey).WriteTo` and `ParseRecoveryKey`; the library has no
recovery-key file I/O.

## Data flow

1. `NewRecoveryKey` draws random bytes
   and renders them in the chosen format. Nothing is written to any volume
   yet.
2. `(*Volume).AddRecoveryKey` adds the rendered credential to a keyslot
   using an unlocked `*Key`, exactly as `AddKeyslot` would for any other
   credential, then writes a `systemd-recovery` token naming the slot. If
   the token write fails, the keyslot is removed again, because a keyslot
   nothing describes cannot be told apart from a forgotten credential — this
   is the library's two-phase design, so the caller is expected to show or
   persist the key **before** calling `AddRecoveryKey`, and there is no
   `RecoveryKey.SaveError` to recover from a print failure after the fact.
3. `(*Volume).Unlock` followed by `(*Key).Destroy` checks the key still opens
   the volume, read-only.

## What this feature deliberately does not do

No offline brute-force resistance beyond the credential's own entropy — the
lower KDF floor is deliberate, not an oversight ("The problem and the shape
chosen", above). No storage of the recovery key anywhere other than where the
caller puts it: the library prints or writes it once and keeps no copy.
