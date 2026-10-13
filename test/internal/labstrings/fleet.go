// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import "regexp"

// This file is the fleet pattern set: the one place this repository writes
// down the fleet's own values. It is stripped at publish (DefaultStripAtPublish,
// .gitattributes), so the published gate spells none of them, and
// DefaultAllowList accepts it, because a pattern cannot be written without
// naming what it finds. A new fleet subnet, port or host family is one entry
// here and one sample in fleet_test.go.
//
// Note what is NOT here: 192.168.0.0/16 at large. Tests across this tree use
// RFC 1918 literals as opaque addresses that are never dialed, and banning the
// whole space would bury the real findings under hundreds of them. The fleet
// subnet is named precisely instead.
func init() {
	fleet = []Pattern{
		{
			Class:    ClassLabAddress,
			Expr:     regexp.MustCompile(`\b192\.168\.101\.\d{1,3}\b`),
			Needle:   "192.168.101.",
			Guidance: "use an RFC 5737 documentation address (198.51.100.0/24) or a name under .example.com",
		},
		{
			// The forge's web and API port, which follows its address or
			// its name in every URL that leaks it.
			Class:    ClassLabAddress,
			Expr:     regexp.MustCompile(`:3001\b`),
			Needle:   ":3001",
			Guidance: "a forge URL belongs in a CI repository variable; an example uses https://forge.example",
		},
		{
			// The forge's ssh port.
			Class:    ClassLabAddress,
			Expr:     regexp.MustCompile(`:2222\b`),
			Needle:   ":2222",
			Guidance: "a forge remote belongs in a CI repository variable; an example uses ssh://git@forge.example/",
		},
		{
			Class:    ClassLabHost,
			Expr:     regexp.MustCompile(`(?i)\bvstation-\d{2}\b`),
			Needle:   "vstation-",
			Guidance: "name the role, not the machine: ci-runner-01, gpu-host.internal, luks.example.com",
		},
		{
			Class:    ClassLabHost,
			Expr:     regexp.MustCompile(`(?i)\bdellemc-\d{2}\b`),
			Needle:   "dellemc-",
			Guidance: "a CI runner's own hostname is never load-bearing: ci-runner-01 reads the same",
		},
		{
			Class:    ClassLabHost,
			Expr:     regexp.MustCompile(`(?i)\bgodlike(\.internal)?\b`),
			Needle:   "gpu-host",
			Guidance: "name the role, not the machine: gpu-host.internal, npu-host.internal",
		},
		{
			Class:    ClassLabHost,
			Expr:     regexp.MustCompile(`(?i)\bomega(\.internal)?\b`),
			Needle:   "omega",
			Guidance: "name the role, not the machine: build-host.internal, batch-runner",
		},
		{
			Class:    ClassLabHost,
			Expr:     regexp.MustCompile(`(?i)\btgw-\d{2}\b`),
			Needle:   "tgw-",
			Guidance: "name the role, not the machine: tunnel-gateway.internal, gateway.example",
		},
		{
			Class:    ClassLabHost,
			Expr:     regexp.MustCompile(`(?i)\bmini-\d{2}\b`),
			Needle:   "mini-",
			Guidance: "name the role, not the machine: agent-01, ci-runner-01",
		},
		{
			// The prefix folds case and the letter does not: the coordinator
			// hosts are written in lower case, and "Control-C" is a key chord.
			Class:    ClassLabHost,
			Expr:     regexp.MustCompile(`(?i:\bcontrol)-[a-z]\b`),
			Needle:   "control-",
			Guidance: "name the role, not the machine: coordinator.internal, forge.example",
		},
		{
			Class:    ClassOwnerPath,
			Expr:     regexp.MustCompile(`/home/jhahn\b`),
			Needle:   "/home/jhahn",
			Guidance: "make the path relative to the repository root, or use /var/lib, /srv, /home/agent",
		},
		{
			Class:    ClassOwnerPath,
			Expr:     regexp.MustCompile(`/mnt/vstation`),
			Needle:   "/mnt/vstation",
			Guidance: "the lab's NFS mount does not exist anywhere else; use a repository-relative path",
		},
		{
			// The forge owner in a module path is a different, public name
			// and does not contain this one; \b keeps longer words out.
			Class:    ClassOwnerAccount,
			Expr:     regexp.MustCompile(`(?i)\bjhahn\b`),
			Needle:   "jhahn",
			Guidance: "name the role, not the person: agent, ci, user@example.com",
			YieldsTo: ClassOwnerPath,
		},
	}
}
