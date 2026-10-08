### Fixed

- **`UnlockWithProvider` tries a token's keyslots by priority (#288).** The
  keyslots the provider's token names are tried `prefer` first, then `normal`,
  then `ignore`, each group in the token's order, as cryptsetup does for a
  token named with `--token-id`. A `normal` keyslot listed first no longer
  wins over a `prefer` one.
