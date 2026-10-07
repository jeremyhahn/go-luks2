# cryptsetup interop — API

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1) and cryptsetup 2.7.5
> Conflicts with this document are defects. Fix them here first.

No API surface of its own: interop is a cross-cutting property of the Go API
documented per feature ([volumes/api.md](../volumes/api.md) and its
siblings), not a capability this folder exposes. go-luks2 is a Layer 0
library (docs/00 §L1 exemption); REST/gRPC/QUIC/MCP/Unix: not applicable to
any feature here, interop included.
