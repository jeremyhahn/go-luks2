// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import "regexp"

// The shapes the fleet pattern set matches. Each is generic and names no fleet
// value; its first submatch is the key that Digest hashes and a pattern's
// Digests are checked against.
var (
	// shapeIPv4 is any dotted-quad address. The key is its /24 prefix, the
	// first three octets, so one digest covers a whole subnet.
	shapeIPv4 = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b`)

	// shapePort is a port after a colon, as in a URL or an ssh remote. The key
	// is the number.
	shapePort = regexp.MustCompile(`:(\d+)\b`)

	// shapeNumberedHost is a <word>-<2 digits> host name. The key is the word.
	shapeNumberedHost = regexp.MustCompile(`(?i)\b([a-z]+)-\d{2}\b`)

	// shapeLetteredHost is a <word>-<letter> host name. The word folds case
	// and the letter does not: such hosts are written in lower case, and
	// "Control-C" is a key chord. The key is the word.
	shapeLetteredHost = regexp.MustCompile(`(?i:\b([a-z]+))-[a-z]\b`)

	// shapeWord is a bare word, optionally under .internal: a host or login
	// name on its own. The key is the word, so a longer word that merely
	// contains a value is a different key.
	shapeWord = regexp.MustCompile(`\b(\w+)(?i:\.internal)?\b`)

	// shapeHomeDir is a /home/<name> path component. The key is the name.
	shapeHomeDir = regexp.MustCompile(`/home/(\w+)`)

	// shapeMount is a /mnt/<name> path component. The key is the name's
	// leading letters.
	shapeMount = regexp.MustCompile(`/mnt/([[:alpha:]]+)`)
)

// This file is the fleet pattern set. A pattern is a shape above and the
// digests of the fleet values that shape may match (Digest); the values
// themselves are written nowhere in this repository. A new fleet subnet, port
// or host family is one digest here, computed outside the tree.
//
// Note what is NOT here: private address space at large. Tests across this
// tree use RFC 1918 literals as opaque addresses that are never dialed, and
// banning the whole space would bury the real findings under hundreds of them.
// The fleet subnet is named precisely instead, by the digest of its /24.
func init() {
	fleet = []Pattern{
		{
			Class:    ClassLabAddress,
			Expr:     shapeIPv4,
			Digests:  []string{"c3da830da769bd8f45c7203550255793e1bc9f0e921beeccd41017e87cac0f66"},
			Guidance: "use an RFC 5737 documentation address (198.51.100.0/24) or a name under .example.com",
		},
		{
			// The forge's web and API port, which follows its address or
			// its name in every URL that leaks it.
			Class:    ClassLabAddress,
			Expr:     shapePort,
			Digests:  []string{"a20c25627ed7bbb6d2b999c589b698e6ecd84384e2e0e510d8869d79a5ad244c"},
			Guidance: "a forge URL belongs in a CI repository variable; an example uses https://forge.example",
		},
		{
			// The forge's ssh port.
			Class:    ClassLabAddress,
			Expr:     shapePort,
			Digests:  []string{"edee29f882543b956620b26d0ee0e7e950399b1c4222f5de05e06425b4c995e9"},
			Guidance: "a forge remote belongs in a CI repository variable; an example uses ssh://git@forge.example/",
		},
		{
			Class:    ClassLabHost,
			Expr:     shapeNumberedHost,
			Digests:  []string{"d7509e2c30b4aa6e7950f93b176ce45cf749a1c5199db383648c2be7a6170a7b"},
			Guidance: "name the role, not the machine: ci-runner-01, gpu-host.internal, luks.example.com",
		},
		{
			Class:    ClassLabHost,
			Expr:     shapeNumberedHost,
			Digests:  []string{"c9f72ed606186d2cab997a7e41e44bd66bb7d8117cb13d2928906884e0090062"},
			Guidance: "a CI runner's own hostname is never load-bearing: ci-runner-01 reads the same",
		},
		{
			Class:    ClassLabHost,
			Expr:     shapeWord,
			Digests:  []string{"b2f896bb37f772a0dd0d4fdae6ec20020143f642ec30edd22c10a759f847bc9b"},
			Guidance: "name the role, not the machine: gpu-host.internal, npu-host.internal",
		},
		{
			Class:    ClassLabHost,
			Expr:     shapeWord,
			Digests:  []string{"304b4a90a76a1cbe4c112e074b30e75181f54df43d60f883597457844293b341"},
			Guidance: "name the role, not the machine: build-host.internal, batch-runner",
		},
		{
			Class:    ClassLabHost,
			Expr:     shapeNumberedHost,
			Digests:  []string{"471db7c8254c7b5fc929214cba734ac9f93f5198893686beb975c05f8e75e4d1"},
			Guidance: "name the role, not the machine: tunnel-gateway.internal, gateway.example",
		},
		{
			Class:    ClassLabHost,
			Expr:     shapeNumberedHost,
			Digests:  []string{"43385991f0be5fed6db7fb640c5f510d41bcaac6ecca6c842a0c2a2d2d2bf510"},
			Guidance: "name the role, not the machine: agent-01, ci-runner-01",
		},
		{
			// The coordinator hosts.
			Class:    ClassLabHost,
			Expr:     shapeLetteredHost,
			Digests:  []string{"0fcd568a5cb9bdb4677b69354b11ee415af8f784519cff3da49a26f84eaee7f2"},
			Guidance: "name the role, not the machine: coordinator.internal, forge.example",
		},
		{
			Class:    ClassOwnerPath,
			Expr:     shapeHomeDir,
			Digests:  []string{"6c47ecac10bc97a16b8ef358127f8630bf8cda0db7213a792ace464465f47419"},
			Guidance: "make the path relative to the repository root, or use /var/lib, /srv, or a home directory named for a role",
		},
		{
			// The lab's NFS mount, named for a workstation.
			Class:    ClassOwnerPath,
			Expr:     shapeMount,
			Digests:  []string{"d7509e2c30b4aa6e7950f93b176ce45cf749a1c5199db383648c2be7a6170a7b"},
			Guidance: "the lab's NFS mount does not exist anywhere else; use a repository-relative path",
		},
		{
			// The forge owner in a module path is a different, public name;
			// the key is a whole word, so a longer word is a different key.
			Class:    ClassOwnerAccount,
			Expr:     shapeWord,
			Digests:  []string{"6c47ecac10bc97a16b8ef358127f8630bf8cda0db7213a792ace464465f47419"},
			Guidance: "name the role, not the person: agent, ci, user@example.com",
			YieldsTo: ClassOwnerPath,
		},
	}
}
