// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package keyprovider implements luks2.KeyProvider with credentials that come
// from outside this process -- a hardware authenticator, an agent, a script --
// rather than from a human at a terminal.
//
// # Why this is exec and not a linked library
//
// FIDO2 interaction is delegated to the libfido2 HELPER BINARIES (fido2-cred,
// fido2-assert) rather than to keys-pub/go-libfido2 or any other binding.
// Linking a binding drags cgo into a package whose consumers cross-compile it
// as pure Go, and it would put a USB transport, a PIN prompt and a device
// enumeration inside a library whose job is to write 4 KiB of JSON correctly.
// The helpers already exist, are packaged everywhere libfido2 is, and speak a
// stable line-oriented protocol.
//
// The consequence is that there is exactly ONE external-credential mechanism
// here: run a command, take a line of its output. Command is that mechanism,
// and FIDO2 is a configuration of it rather than a second implementation. A
// TPM helper, a network agent or a smartcard script needs no new code in this
// package.
//
// # Core dumps
//
// A helper's output line is read into locked memory, but the KDF and cipher
// code a passphrase later reaches makes plain heap copies, so an application
// that uses these providers must call enclave.HardenProcess from its own main
// to keep core dumps off (see package luks2). This package never calls it.
package keyprovider
