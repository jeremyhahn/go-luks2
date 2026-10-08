### Removed — BREAKING: `luks2 addkey --kdf` is gone

- **`addkey` takes the same KDF options as `create` (#287).** The combined
  `--kdf pbkdf2-sha512` spelling is removed, with no replacement flag of that
  name. Use `--pbkdf`, `--hash`, `--iter-time`, `--pbkdf-force-iterations`,
  `--pbkdf-memory` and `--pbkdf-parallel`. A script that passed `--kdf` now
  fails with a usage error instead of being silently accepted.
