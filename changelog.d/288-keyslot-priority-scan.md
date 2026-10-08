### Changed

- **BREAKING: `Unlock` honours keyslot priority (#288).** The scan tries every
  `prefer` keyslot before any `normal` one and no longer tries an `ignore`
  keyslot at all, as cryptsetup does when no keyslot is named. A passphrase
  that opens only an `ignore` keyslot now fails `Unlock` (and `luks2 open`)
  with `ErrWrongKey`, or with `ErrNoKeyslots` when every bound keyslot is
  `ignore`; `UnlockKeyslot` still opens it by number. `Key.Keyslot()` reports
  a `prefer` keyslot when one opens.
