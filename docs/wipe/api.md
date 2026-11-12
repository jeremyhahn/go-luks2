# Wipe — API

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

The Go API, embedded transport only. go-luks2 is an embedded Go
library; it has no REST, gRPC, QUIC, MCP or Unix-socket transport.

| Capability | Embedded (Go call) |
|---|---|
| Header-only crypto-erase | `(*luks2.Volume).Erase(ctx) error` |
| Full-device sanitize | `wipe.Sanitize(ctx, path, wipe.Params) error` |
| Zero one keyslot area | `(*luks2.Volume).RemoveKeyslot(ctx, slot) error` |

Crypto-erase and full-device sanitization are two separate calls; neither
takes a mode flag that selects the other.

## `pkg/wipe` identifiers

| Identifier | Meaning |
|---|---|
| `Sanitize(ctx context.Context, path string, p Params) error` | Overwrite the whole device, verify if asked, sync |
| `Params` (`Standard`, `Patterns`, `Verify`, `Discard`, `Progress`) | What `Sanitize` writes; the zero value is one `Zeros` pass |
| `Progress` (`Pass`, `Passes`, `Written`, `Total`, `Pattern`, `Verifying`) | Reported to `Params.Progress` after every chunk |
| `Pattern`, `Zeros`, `Ones`, `Random`, `(Pattern).String()` | One pass's content |
| `Standard`, `NoStandard`, `DoD3Pass`, `DoD7Pass`, `NIST`, `(Standard).String()`, `(Standard).Patterns()` | A fixed pass sequence; it overrides `Params.Patterns` |
| `VerifyMode`, `VerifyDefault`, `VerifyAlways`, `VerifyNever` | Read-back verification: the standard's default, always, never |
| `ErrVerification` | The medium does not hold what the last pass wrote |
| `ErrDeviceInUse`, `ErrDeviceChanged`, `ErrPermissionDenied`, `ErrLockContended`, `LockTimeoutError` | The device is held, was replaced, may not be opened, or its lock is taken |
| `Error` | The typed error every failure is (`errors.Is` against the sentinels above) |

No request/response schema, status code mapping or `scp` permission applies.
See [volumes/api.md](../volumes/api.md) for the general Layer 0 statement
this folder inherits.
