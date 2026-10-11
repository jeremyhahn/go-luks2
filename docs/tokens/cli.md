# Tokens — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (f871541)
> Conflicts with this document are defects. Fix them here first.

```
luks2 token list   <device>
luks2 token show   <device> <id>
luks2 token export <device> <id> [--file <path>]
luks2 token import <device> <id> --file <path>
luks2 token remove <device> <id>
luks2 token free   <device>
luks2 token exists <device> <id>
luks2 token count  <device>
```

Tokens are header metadata saying what opens a keyslot. They hold no key
material. Ids are 0–31. Format and types:
[engineering.md](engineering.md#token-types).

```
$ luks2 token list /srv/data.luks
Slot  Type                 Keyslots
0     systemd-recovery     [1]
1     systemd-tpm2         [2]
```

- `show` and `export` print the token as indented JSON, including members this
  tool does not model. `export --file <path>` writes it to a file; `--file -`
  or no `--file` writes to standard output.
- `import` requires `--file`; `-` reads standard input. At most 64 KiB is read.
  The JSON is validated by the library and replaces any token with that id.
- `remove` deletes the token only. **The keyslot still opens the volume**; to
  revoke the credential use [`killslot`](../keyslots/cli.md#removekey-and-killslot).
- `free` and `count` print a bare number. `exists` answers in its exit status:
  0 present, 1 absent. Other failures keep their own
  [exit status](../volumes/cli.md#exit-status).

```bash
sudo luks2 token export /dev/sdb1 0 --file token0.json
sudo luks2 token export /dev/sdb1 0 | sudo luks2 token import /dev/sdb1 1 --file -
if sudo luks2 token exists /dev/sdb1 0; then echo present; fi
```
