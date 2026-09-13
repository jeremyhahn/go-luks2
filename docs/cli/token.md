# luks2 token

Tokens are the header metadata that says **what** opens a keyslot — a hardware
authenticator, a TPM, an external agent.

A token holds **no key material**. It is the record that lets an implementation
find the credential for a keyslot, which is why it can be exported, edited and
imported as plain JSON.

## Synopsis

```
luks2 token list   <device>
luks2 token show   <device> <id>
luks2 token export <device> <id> [--file <path>]
luks2 token import <device> <id>  --file <path>
luks2 token remove <device> <id>
luks2 token free   <device>
luks2 token exists <device> <id>
luks2 token count  <device>
```

Token ids run from 0 to 31.

## Token types this tool writes

| Type | Written by | What it says |
|---|---|---|
| `systemd-recovery` | [`recovery add`](recovery.md) | This keyslot is a recovery key |
| `systemd-fido2` | the library's key providers | This keyslot is unlocked by a FIDO2 authenticator |

Both spellings are systemd's, so `cryptsetup luksDump` and `systemd-cryptsetup`
recognise what they describe.

## list

```bash
$ sudo luks2 token list /dev/sdb1
Slot  Type                 Keyslots
0     systemd-fido2        [1]
1     systemd-tpm2         [2]
```

Listed in slot order. A key on the device that no LUKS2 implementation can
address — a non-canonical spelling such as `"01"`, or a number outside the
range — is not listed, because nothing can retrieve it either.

## show, export and import

`show` prints the token as indented JSON. `export` produces the same document
for a pipe or a file; `import` reads one back.

```bash
sudo luks2 token show /dev/sdb1 0

# To a file, and back
sudo luks2 token export /dev/sdb1 0 --file token0.json
sudo luks2 token import /dev/sdb1 0 --file token0.json

# Through a pipe
sudo luks2 token export /dev/sdb1 0 | sudo luks2 token import /dev/sdb1 1 --file -
```

`--file -` means standard input for `import` and standard output for `export`.
`export` with no `--file` also writes to standard output. `import` requires
`--file`; there is no default source for something that overwrites a header.

The document must be under 64 KiB. The whole LUKS2 JSON area is at most 4 MiB
and one token is a small part of it.

## remove

```bash
sudo luks2 token remove /dev/sdb1 0
```

**Removing a token revokes nothing.** The keyslot it named still opens the
volume; what is gone is the record of what opens it. To revoke the credential
itself use [`luks2 killslot`](keyslots.md). The command says so every time,
because it is the thing operators get wrong.

## free, exists and count

Written for scripts. `free` and `count` print a bare number; `exists` answers in
its **exit code**, 0 for present and 1 for absent, so nothing has to be parsed.

```bash
slot=$(sudo luks2 token free /dev/sdb1)

if sudo luks2 token exists /dev/sdb1 0; then
    echo "token 0 is there"
fi
```

## Exit codes

| Code | Description |
|---|---|
| 0 | Success — for `exists`, the token is present |
| 1 | The token is absent, the arguments were unusable, or the operation failed |

## See Also

- [LUKS2 tokens](../luks/tokens.md) — the on-disk structure and the field names
- [External key providers](../luks/keyprovider.md) — enrolling a credential a token describes
- [keyslots](keyslots.md) — the credential a token points at
