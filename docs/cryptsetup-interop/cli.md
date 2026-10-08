# cryptsetup interop — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163) and cryptsetup 2.7.5
> Conflicts with this document are defects. Fix them here first.

No CLI surface: `luks2` has no `interop` or `compat` verb. The interop
policy and matrix in [architecture.md](architecture.md) and
[engineering.md](engineering.md) apply to every `luks2` command and every
`cryptsetup` command against the same volume equally — there is nothing to
select or configure at the command line.

A reader looking for "which `luks2` command does what `cryptsetup` command
does" should start from the command's own feature folder:
[volumes/cli.md](../volumes/cli.md), [keyslots/cli.md](../keyslots/cli.md),
[recovery-keys/cli.md](../recovery-keys/cli.md),
[tokens/cli.md](../tokens/cli.md), [header/cli.md](../header/cli.md),
[wipe/cli.md](../wipe/cli.md).
