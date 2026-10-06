// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package header is the LUKS2 on-disk format: the binary header and its JSON
// metadata, the canonical-JSON codec, the passthrough for JSON members this
// module does not model, checksums, requirements, the structural checks
// cryptsetup applies to a header's segments, keyslots and digests, and the
// keyslot scan order.
//
// It may import internal/kdf, internal/fips and internal/errs, and nothing
// else in this module: no internal/secret, no internal/device, no
// internal/clock. It holds no key material and performs no I/O of its own --
// every function here works on bytes or an io.ReaderAt/io.Writer a caller
// already has open, never a device path. The caller (pkg/luks2) owns the
// device, the lock and the lifetime of any secret; this package only knows
// the shape of what is written to, or read from, a header area.
//
// It defines no package-level mutable seam var. A seam a caller needs to
// substitute -- a random source, a UUID generator, an fsync -- is a
// parameter, never a global.
package header
