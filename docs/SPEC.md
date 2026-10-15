# go-luks2 specification

> **Status: NORMATIVE** · Owner: Software Department · Last verified: 2026-10-14 against be49afb
> Conflicts with this document are defects. Fix them here first.

A feature listed in SPEC.md, in any status, is never deleted: not its docs,
code or issues. Removing or re-scoping a feature needs the owner's change to
SPEC.md.

## Purpose

go-luks2 is a pure Go library and command-line tool for LUKS2 disk encryption. It
formats, unlocks and manages LUKS2 volumes in process, without the cryptsetup
binary, and the volumes interoperate with cryptsetup in both directions.

- Layer: a Layer 0 library of the portfolio. go-trusted-platform consumes it
  for encrypted volume management.
- Embedded library: go-enclave, the locked-memory primitive, is the one
  portfolio project go-luks2 embeds, and it embeds it as a library.
- Inherited: go-enclave's locked-memory custody. Key material stays in
  go-enclave locked memory for its whole lifetime.
- Re-exported: credentials and keys cross the `pkg/luks2` and `pkg/keyprovider`
  API as go-enclave's own `*enclave.Memory`, unchanged and not renamed.
  go-enclave's functions, such as `enclave.HardenProcess`, are not
  re-exported: a consumer imports go-enclave to call them.

## Boundaries

go-luks2 is embedded in its consumer's process as a library and is never run
as a second product. It runs no cluster, engine, database or service of its
own, and adds no second store beside its consumer's. The only state it writes
is on the volume itself: the LUKS2 header, keyslots and tokens, in
cryptsetup's format.

go-luks2 owns:

- The LUKS2 on-disk format as cryptsetup defines it: header, JSON metadata,
  keyslots, tokens and the data segment description.
- Turning a credential into the volume key, and handing that key to dm-crypt
  through the kernel keyring.
- The device layer a volume needs: loop devices, filesystems on a mapping,
  crypto-erase and full-device sanitization.
- Custody of every key it handles, in go-enclave protected memory. Failing to
  obtain locked memory fails the operation; there is no heap fallback.

go-luks2 never:

- Runs the cryptsetup binary, or any external command, in the `pkg/luks2`
  core. The core is rootless and exec-free.
- Exposes a service transport: no REST, gRPC, QUIC, MCP or Unix-socket form.
  It is an embedded Go library and a CLI.
- Imports any portfolio module other than go-enclave.
- Defines an on-disk format of its own. A header it writes opens in
  cryptsetup, and a header cryptsetup writes opens here.
- Contains TPM, HSM or KMS code. Hardware-backed keys come in through
  `Volume.UnlockWithVolumeKey` or a `KeyProvider`.
- Opens or converts LUKS1, performs online reencryption, activates a
  dm-integrity segment or activates a detached header.
- Resizes or suspends a live mapping, benchmarks KDFs, rewrites a volume's
  UUID or label, or backs a header up to a file. A volume's owner runs those
  with cryptsetup on the same container.
- Logs. Errors are typed and returned.
- Runs anywhere but Linux.

## Features

Status is one of shipped, in progress, planned or future.

| Feature | Status | Requirements | Detail |
|---|---|---|---|
| volumes | shipped | Create, open, unlock, mount and close a LUKS2 container; the package layout along trust boundaries; key custody; the typed error model; the project-wide test strategy. Every `pkg/` export is named in a feature folder. See [architecture](volumes/architecture.md). | [docs/volumes/](volumes/) |
| keyslots | shipped | Up to 32 keyslots wrap one volume key under different credentials; credentials are added and revoked without re-encrypting data; PBKDF2 and Argon2 costs are inherited and floored; the last bound keyslot is never removed. See [architecture](keyslots/architecture.md). | [docs/keyslots/](keyslots/) |
| recovery-keys | shipped | Generate a random recovery credential from the library's CSPRNG, store it in an ordinary keyslot with its own KDF floor, and record it with a `systemd-recovery` token. See [architecture](recovery-keys/architecture.md). | [docs/recovery-keys/](recovery-keys/) |
| tokens | shipped | Read and write header token metadata in slots 0–31 with no key material; produce credentials from outside the process through `KeyProvider` (helper commands, FIDO2). See [architecture](tokens/architecture.md). | [docs/tokens/](tokens/) |
| header | shipped | Read and write cryptsetup's binary header and JSON metadata, both copies; bound a header this library did not write (damaged or hostile) before spending CPU or locked memory on it; repair the primary copy from the secondary. See [architecture](header/architecture.md). | [docs/header/](header/) |
| dm-crypt-activation | shipped | Turn an unlocked volume key into `/dev/mapper/<name>` by loading a dm-crypt table built from the header; roll back a failed activation; tear a mapping down. Lives in `pkg/dmcrypt` only. See [architecture](dm-crypt-activation/architecture.md). | [docs/dm-crypt-activation/](dm-crypt-activation/) |
| kernel-keyring | shipped | Hand the volume key to dm-crypt as a `logon` keyring reference, never inline in the table; a startup preflight proves the keyring works; a keyring that cannot hold the key fails the operation. See [architecture](kernel-keyring/architecture.md). | [docs/kernel-keyring/](kernel-keyring/) |
| loop-devices | shipped | Attach a regular file as a block device, find it by the backing file's device and inode, and detach it, refusing a device no longer backed by that file. See [architecture](loop-devices/architecture.md). | [docs/loop-devices/](loop-devices/) |
| filesystems | shipped | Make, check, repair, detect and inspect filesystems on a block device path, and mount and unmount them; independent of LUKS2. See [architecture](filesystems/architecture.md). | [docs/filesystems/](filesystems/) |
| wipe | shipped | Crypto-erase destroys the header copies and keyslots; full-device sanitization overwrites the device. They are two separate calls, not one call with a mode flag. See [architecture](wipe/architecture.md). | [docs/wipe/](wipe/) |
| fips | shipped | Run under the Go Cryptographic Module in FIPS 140-3 mode; refuse Argon2 and SHA-1 keyslots in FIPS mode and never write SHA-1; import an existing volume onto approved KDFs with `MigrateToFIPS`. See [architecture](fips/architecture.md). | [docs/fips/](fips/) |
| cryptsetup-interop | shipped | The format is cryptsetup's, and interop runs both ways; a stricter check never stops a cryptsetup-written volume from opening; the measured two-way interop matrix. See [architecture](cryptsetup-interop/architecture.md). | [docs/cryptsetup-interop/](cryptsetup-interop/) |
| release | in progress | Publish the project to its public mirror as the archive export of a signed, annotated release tag; the published tree carries no fleet value and no internal-only file; versions follow the [versioning policy](README.md#versioning-policy). See [Release criteria](#release-criteria). | [docs/release/](release/) |

## Interfaces

- SDK: [`pkg/luks2`](volumes/api.md), the rootless, exec-free core.
- SDK: [`pkg/dmcrypt`](dm-crypt-activation/api.md), activation and the [kernel keyring](kernel-keyring/api.md).
- SDK: [`pkg/keyprovider`](tokens/api.md), credential providers that exec a helper.
- SDK: [`pkg/loop`](loop-devices/api.md), loop devices.
- SDK: [`pkg/filesystem`](filesystems/api.md), filesystems.
- SDK: [`pkg/wipe`](wipe/api.md), full-device sanitization.
- CLI: [`luks2`](volumes/cli.md) (`cmd/luks2`), with each feature folder's `cli.md`.
- API transport: none. See [Boundaries](#boundaries).

## Release criteria

The dev-complete milestone (M7) closes when every item in the first list
below is true. Until go-trusted-platform is dev complete too, only `-alpha`
tags are cut; an `-rc.N` is cut only if something needs one, and the
release-candidate tags already cut stay as they are. Release candidates,
staging and the release come after, in the second list: `v1.0.0` is cut after
the release candidate, once every item in both lists is true.

Dev complete:

- Every feature row in [Features](#features) is shipped, apart from release,
  whose publish steps are the second list. Done.
- Every seam row that go-trusted-platform's SPEC names on go-luks2 is
  shipped. Today that is its `luks` feature row (add a passphrase, bind FIDO2
  or the TPM, cut a recovery key, retire a slot, rotate a passphrase, under
  the FIPS keyslot policy), which rests on keyslots, tokens, recovery-keys
  and fips here; and its release criterion "a real backend on go-luks2; FIPS
  activation restrictions hold", which rests on dm-crypt-activation and fips
  here. Open, outside this repository.
- The API is stable: the `pkg/` exports named in the feature folders do not
  change before `v1.0.0`. Open.
- CI and the FIPS gate are green on `main`. Done.
- CI conforms to the CI standard (`ci-standard.md`): build, unit tests,
  integration tests, security scans and a latest-version check, all in the
  project's devcontainer image. Open.
- Releases are signed: the release target writes the version commit and an
  annotated tag through the agent's signing identity, and fails closed
  without it. Done.
- Every document carries its status banner and `Last verified:` stamp. Done.
- `docs/SPEC.md` and `ROADMAP.md` are present and agree. Done.
- go-enclave is pinned at a release candidate. Done.
- The internal-only files are excluded from the archive export, and the
  releasability gate passes on that export. Done.

After dev complete, once go-trusted-platform is dev complete:

- A release candidate is tagged and checked from a consumer's point of view
  after the tag exists. Open.
- go-enclave has a final release, pinned here before `v1.0.0`. Open, outside
  this repository.
- The joint staging run has passed. Open, run by the owner.
- The owner has approved the publish to the public mirror and chosen the
  public version. Open, owner-gated.
