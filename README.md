# go-luks2

A Go library and command-line tool for LUKS2 disk encryption. Formatting,
keyslots, headers and the dm-crypt mapping are done in process, without
cryptsetup. Volumes interoperate with cryptsetup in both directions.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The project is pre-1.0. See [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) for
what a version number promises.

## Install

```bash
go install github.com/jeremyhahn/go-luks2/cmd/luks2@latest   # CLI
go get github.com/jeremyhahn/go-luks2/pkg/luks2               # library
```

## Requirements

- Linux with device-mapper and kernel keyring support (`CONFIG_KEYS`). In a
  container, seccomp must allow `add_key`, `keyctl` and `request_key`; see
  [Kernel keyring](docs/ARCHITECTURE.md#kernel-keyring).
- Root for anything that creates a mapping, a loop device or a mount. Reading
  or editing the header of a file you own does not need root.
- `RLIMIT_MEMLOCK` headroom of about 1 MiB per concurrent operation. See
  [Key custody](docs/ARCHITECTURE.md#key-custody).
- `mkfs.ext4`, `mkfs.xfs` or `mkfs.fat` when the CLI's `create` is asked to
  make a filesystem. Everything else in the CLI is pure Go.
- Go 1.27.0 to build.

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

Every command, flag and exit code is in the [CLI reference](docs/cli/README.md).
Scripts and systemd units pass passphrases with `--key-file`; see
[key input](docs/cli/key-input.md).

## Library quick start

```go
package main

import (
	"errors"
	"log"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func main() {
	// Fails at startup, not at the first unlock, if the kernel keyring
	// syscalls are blocked.
	if err := luks2.CheckKeyringAvailable(); err != nil {
		log.Fatal(err)
	}

	pass := []byte("correct horse battery staple")
	if err := luks2.Format(luks2.FormatOptions{
		Device:     "/dev/sdb1",
		Passphrase: pass,
		Label:      "backup",
	}); err != nil {
		log.Fatal(err)
	}

	if err := luks2.Unlock("/dev/sdb1", pass, "backup"); err != nil {
		if errors.Is(err, luks2.ErrMappingStillLive) {
			log.Print("unlock failed and its rollback did not finish; close the mapping")
		}
		log.Fatal(err)
	}
	defer func() { _ = luks2.Lock("backup") }()
}
```

The [library guide](docs/luks/README.md) covers the API by task, the errors to
branch on, and the on-disk format.

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Packages, key custody, on-disk handling, device layer, trust boundaries |
| [docs/luks/](docs/luks/README.md) | Library guide and LUKS2 format notes |
| [docs/cli/](docs/cli/README.md) | CLI reference |
| [docs/FIPS.md](docs/FIPS.md) | FIPS 140-3 mode, approved KDFs, importing Argon2 volumes |
| [docs/TESTING.md](docs/TESTING.md) | Test tiers, coverage gate, the integration container |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | Versioning policy; interoperability with cryptsetup, and where this library is stricter |
| [docs/RELEASABILITY.md](docs/RELEASABILITY.md) | What may be published, and the gate that checks it |
| [changelog.d/](changelog.d/README.md) | How changelog entries are written |

## Development

```bash
make ci                # format, vet, lint, security scans, releasability, unit tests, coverage gate, build
make integration-test  # integration suite in a scoped container (needs Docker)
make help              # every target
```

## Limitations

- Linux only.
- LUKS2 only. LUKS1 headers are detected by `IsLUKS` but not opened.
- Keyslot areas are AES: `aes-xts-plain64` is written; `aes-xts-plain`,
  `aes-cbc-essiv:sha256`, `aes-cbc-plain64` and `aes-cbc-plain` are also read.
  The data segment cipher is passed to dm-crypt as the header declares it.
- No online reencryption and no dm-integrity: such containers are refused for
  activation with a typed error. Detached headers are read and their keyslots
  managed, but not activated. See [COMPATIBILITY.md](docs/COMPATIBILITY.md).

## License

Apache License 2.0. Author: Jeremy Hahn.
