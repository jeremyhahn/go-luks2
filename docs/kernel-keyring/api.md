# Kernel keyring — API

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (f871541)
> Conflicts with this document are defects. Fix them here first.

go-luks2 is a Layer 0 library: the embedded Go call is the only transport, and
REST, gRPC, QUIC, MCP and Unix-socket forms do not apply (same exemption as
[volumes/api.md](../volumes/api.md)).

| Capability | Embedded Go call |
|---|---|
| Startup preflight | `dmcrypt.CheckKeyring(ctx context.Context) error` |
| Inspect a failure | `*dmcrypt.KeyringError` (`Op`, `Kind`, `Err`), `(*KeyringError).Remedy() string` |
| Match a failure | `errors.Is` against `dmcrypt.ErrKeyring`, `ErrKeyringUnavailable`, `ErrKeyringBlocked`, `ErrKeyringUnsupported`, `ErrKeyringQuotaExhausted`, `ErrKeyringFailed`, `ErrKeyringEntryExists`, `ErrKeyringKeyNotReleased` |

The import path is `github.com/jeremyhahn/go-luks2/pkg/dmcrypt`. The keyring
is also exercised, with no separate call, by `dmcrypt.Activate`; its errors
are the same values.

```go
if err := dmcrypt.CheckKeyring(ctx); err != nil {
	var ke *dmcrypt.KeyringError
	if errors.As(err, &ke) {
		log.Printf("keyring unusable (%s): %s", ke.Op, ke.Remedy())
	}
	return err
}
```

Semantics, error table and matching rules: [engineering.md](engineering.md#error-semantics).
There is no permission model, pagination or status-code mapping; this library
has no process boundary. A consumer that re-exposes volume operations over a
transport documents that mapping in its own repository.

Versioning: the names above are the exported surface of `pkg/dmcrypt`; changes
follow the repository's API-diff check. `CheckKeyring` replaces the earlier
`CheckKeyringAvailable` and `KeyringError` replaces `KeyringUnavailableError`.
