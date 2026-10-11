### Fixed

- **`luks2 open` and `luks2 close` now exit 5, not 1, when the mapping already exists or is busy (#322).** `dmcrypt.ErrActive` and `dmcrypt.ErrBusy` were missing from the exit-status table, so a script testing for cryptsetup(8)'s "exists or busy" status never saw it. Scripts that treated exit 1 as the signal for these two cases must now check for 5.
