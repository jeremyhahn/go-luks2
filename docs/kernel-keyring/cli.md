# Kernel keyring — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-12 against 7ee49b8
> Conflicts with this document are defects. Fix them here first.

No verb of its own: the keyring is exercised by `luks2 open`, and by
`luks2 create` when it is given a file, which opens the new volume as
`luks-auto`. There is no preflight verb; `CheckKeyring` is a library call
([api.md](api.md)).

Flags, arguments and exit codes for both verbs are in
[volumes/cli.md](../volumes/cli.md#open). What this feature adds to them is the
failure a keyring problem produces:

| Message contains | Meaning | Fix |
|---|---|---|
| `could not` … `keyring` | The keyring syscalls are blocked, unsupported, over quota or refused. The message ends with the remedy for the specific cause. | See [user.md](user.md#troubleshooting). |

A keyring entry that cannot be released fails the verb as well, and its message
gives the `keyctl` commands that remove it.

```bash
sudo luks2 open /dev/sdb1 backup
```

Inside a container, the run needs a seccomp profile that allows `add_key`,
`keyctl` and `request_key`.
