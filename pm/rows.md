# SPEC rows

One SPEC row = one row issue = one branch `row/<issue>-<row>` = one lane session = one PR (handbook `software/conventions/sdlc.md` §2b). Every open issue sits under its row issue or is listed below. Rows are in [docs/SPEC.md](../docs/SPEC.md) order.

| Row | Row issue | Status | Folded issues | Open PRs |
|---|---|---|---|---|
| fips | #477 | shipped | 0 | #472 |

Rows with no open work: `volumes`, `keyslots`, `recovery-keys`, `tokens`, `header`, `dm-crypt-activation`, `kernel-keyring`, `loop-devices`, `filesystems`, `wipe`, `cryptsetup-interop`, `release`.

## Open items outside the rows

- #459 ci-template v1.35.2 adoption: CI configuration, not a SPEC row; left to land on its own.
