# go-luks2

A Go library and command-line tool for LUKS2 disk encryption. Formatting,
keyslots, headers and the dm-crypt mapping are done in process, without
cryptsetup. Volumes interoperate with cryptsetup in both directions.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The project is at release candidate `v1.0.0-rc.3` for `1.0.0`. See
[docs/README.md](docs/README.md#versioning-policy) for what a version number
promises and the compatibility policy.

## Install

```bash
go install github.com/jeremyhahn/go-luks2/cmd/luks2@latest   # CLI
go get github.com/jeremyhahn/go-luks2/pkg/luks2               # library
```

## Requirements

- Linux with device-mapper and kernel keyring support (`CONFIG_KEYS`). In a
  container, seccomp must allow `add_key`, `keyctl` and `request_key`; see
  [Kernel keyring](docs/volumes/architecture.md#kernel-keyring).
- Root for anything that creates a mapping, a loop device or a mount. Reading
  or editing the header of a file you own does not need root.
- `RLIMIT_MEMLOCK` headroom of about 1 MiB per concurrent operation. See
  [Key custody](docs/volumes/architecture.md#key-custody).
- `mkfs.ext4`, `mkfs.xfs` or `mkfs.fat` when the CLI's `create` is asked to
  make a filesystem. Everything else in the CLI is pure Go.
- Go 1.27.1 to build.

## CLI quick start

The CLI resolves relative paths against the working directory. The library
itself takes absolute device and container-file paths only.

```bash
# A file-backed volume: creates the file, formats it, attaches a loop
# device, opens it as /dev/mapper/luks-auto and runs mkfs.ext4.
sudo luks2 create /srv/secret.luks 500M ext4
sudo luks2 mount luks-auto /mnt/secret
sudo luks2 unmount /mnt/secret
sudo luks2 close luks-auto

# A block device: formats only.
sudo luks2 create /dev/sdb1
sudo luks2 open /dev/sdb1 backup
sudo mkfs.ext4 /dev/mapper/backup
```

Every command, flag and exit code is in the [CLI reference](docs/volumes/cli.md)
and its sibling feature folders (see [Documentation](#documentation), below).
Scripts and systemd units pass passphrases with `--key-file`; see
[key input](docs/volumes/cli.md#key-input).

## Library quick start

Open the container, format it, unlock it, activate the dm-crypt mapping,
mount a filesystem on it, and tear both down:

```go
package main

import (
	"context"
	"errors"
	"log"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func main() {
	ctx := context.Background()

	// Fails at startup, not at the first activation, if the kernel keyring
	// syscalls are blocked.
	if err := dmcrypt.CheckKeyring(ctx); err != nil {
		log.Fatal(err)
	}

	v, err := luks2.Open(ctx, "/dev/sdb1")
	if err != nil {
		log.Fatal(err)
	}
	defer v.Close()

	pass, err := enclave.NewMemoryEnclave([]byte("correct horse battery staple"))
	if err != nil {
		log.Fatal(err)
	}
	defer pass.Destroy()

	if err := v.Format(ctx, pass, luks2.FormatParams{Label: "backup"}); err != nil {
		log.Fatal(err)
	}

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		if errors.Is(err, luks2.ErrWrongKey) {
			log.Print("wrong passphrase, or the keyslot is damaged")
		}
		log.Fatal(err)
	}
	defer key.Destroy()

	mapping, err := dmcrypt.Activate(ctx, v, key, "backup")
	if err != nil {
		if errors.Is(err, dmcrypt.ErrStillLive) {
			log.Print("activation failed and its rollback did not finish; close the mapping")
		}
		log.Fatal(err)
	}
	defer func() { _ = dmcrypt.Deactivate(ctx, "backup") }()

	if err := filesystem.Make(ctx, mapping.Path(), filesystem.Ext4, filesystem.MakeParams{}); err != nil {
		log.Fatal(err)
	}
	if err := filesystem.Mount(ctx, filesystem.MountParams{
		Source: mapping.Path(), Target: "/mnt/backup", Type: filesystem.Ext4,
	}); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = filesystem.Unmount(ctx, "/mnt/backup", 0) }()
}
```

The [volumes engineering guide](docs/volumes/engineering.md) covers the API
by task, the errors to branch on, and key custody; the on-disk format is
[docs/header/architecture.md](docs/header/architecture.md).

## Documentation

Documentation is organized as one feature folder per CLI command group, each
with architecture, engineering, CLI, API and user-guide pages; start at
[docs/README.md](docs/README.md) for the index and versioning policy.

| Folder | Contents |
|---|---|
| [docs/volumes/](docs/volumes/) | Create, open, mount, close; packages, key custody, device layer, trust boundaries |
| [docs/keyslots/](docs/keyslots/) | Keyslot structure, KDF, cost inheritance, removal |
| [docs/recovery-keys/](docs/recovery-keys/) | Generated recovery credentials |
| [docs/tokens/](docs/tokens/) | Header token metadata, key providers (FIDO2, helper commands) |
| [docs/header/](docs/header/) | On-disk layout, binary header, JSON metadata |
| [docs/wipe/](docs/wipe/) | Crypto-erase and full-device sanitization |
| [docs/fips/](docs/fips/) | FIPS 140-3 mode, approved KDFs, importing Argon2 volumes |
| [docs/cryptsetup-interop/](docs/cryptsetup-interop/) | Versioning policy; interoperability with cryptsetup, and where this library is stricter |
| [docs/volumes/engineering.md](docs/volumes/engineering.md#test-strategy) | Test tiers, coverage gate, the integration container |
| [`test/internal/labstrings`](test/internal/labstrings/labstrings.go) | What may be published, and the gate that checks it (package documentation) |
| [changelog.d/](changelog.d/README.md) | How changelog entries are written |

## Development

```bash
make ci                # format, vet, lint, security scans, releasability, unit tests, coverage gate, build
make integration-test  # integration suite in a scoped container (needs Docker)
make help              # every target
```

## Limitations

- Linux only.
- LUKS2 only. `(*Volume).Header` reports a LUKS1 header with `ErrNotLUKS2`;
  it is not opened.
- Keyslot areas are AES: `aes-xts-plain64` is written; `aes-xts-plain`,
  `aes-cbc-essiv:sha256`, `aes-cbc-plain64` and `aes-cbc-plain` are also read.
  The data segment cipher is passed to dm-crypt as the header declares it.
- No online reencryption and no dm-integrity: such containers are refused for
  activation with a typed error. Detached headers are read and their keyslots
  managed, but not activated. See
  [cryptsetup-interop](docs/cryptsetup-interop/architecture.md).

## License

Apache License 2.0. Author: Jeremy Hahn.
