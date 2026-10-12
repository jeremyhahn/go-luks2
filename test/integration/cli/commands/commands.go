// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package commands holds the CommandDefinition/ArgDefinition table
// the CLI parity suite is checked against: one entry per verb
// internal/cli's registry answers to, crossed by test/integration/cli's own
// runner against the columns {CLI binary, embedded}. It carries no build
// tag and no dependency on internal/cli or pkg/luks2 -- the table is data,
// so that nothing about running it requires root or a real device; only
// the runner and the enumerating test that reads it do.
//
// The table grows with internal/cli's registry: it holds exactly the verbs
// the registry answers to, and the enumerating test fails when it falls
// behind.
package commands

// ArgDefinition is one positional argument a command takes, in order.
type ArgDefinition struct {
	// Name documents what the argument is, e.g. "device" or "mountpoint".
	Name string
	// Required is false for create's trailing "size" and "filesystem":
	// both are only meaningful (and read) for a new file volume, and are
	// ignored outright for a block device. Every other argument in this
	// table is required.
	Required bool
}

// CommandDefinition is one verb the CLI registers, by the same name
// RegisteredVerbs reports: "<verb>" for a bare command, "<verb> <sub>" for
// one entry of a command group (e.g. "header restore").
type CommandDefinition struct {
	Verb string
	Args []ArgDefinition
}

// RequiredArgCount is how many of Args are Required -- the argument count
// a call with none of them supplied falls short of, used by the runner's
// "every verb refuses a call missing its required arguments, identically
// through the CLI binary and embedded" parity case.
func (c CommandDefinition) RequiredArgCount() int {
	n := 0
	for _, a := range c.Args {
		if a.Required {
			n++
		}
	}
	return n
}

// Commands is the table: one CommandDefinition per verb internal/cli.
// RegisteredVerbs returns today. test/integration/cli's enumerating test
// fails when a registry verb has no entry here.
var Commands = []CommandDefinition{
	{Verb: "create", Args: []ArgDefinition{
		{Name: "path", Required: true},
		{Name: "size"},
		{Name: "filesystem"},
	}},
	{Verb: "open", Args: []ArgDefinition{
		{Name: "device", Required: true},
		{Name: "name", Required: true},
	}},
	{Verb: "close", Args: []ArgDefinition{
		{Name: "name", Required: true},
	}},
	{Verb: "mount", Args: []ArgDefinition{
		{Name: "name", Required: true},
		{Name: "mountpoint", Required: true},
	}},
	{Verb: "unmount", Args: []ArgDefinition{
		{Name: "mountpoint", Required: true},
	}},
	{Verb: "info", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "keyslots", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "testkey", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "addkey", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "changekey", Args: []ArgDefinition{
		{Name: "device", Required: true},
		{Name: "slot", Required: true},
	}},
	{Verb: "removekey", Args: []ArgDefinition{
		{Name: "device", Required: true},
		{Name: "slot", Required: true},
	}},
	{Verb: "killslot", Args: []ArgDefinition{
		{Name: "device", Required: true},
		{Name: "slot", Required: true},
	}},
	{Verb: "recovery generate"},
	{Verb: "recovery add", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "recovery verify", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "token list", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "token show", Args: []ArgDefinition{
		{Name: "device", Required: true},
		{Name: "id", Required: true},
	}},
	{Verb: "token export", Args: []ArgDefinition{
		{Name: "device", Required: true},
		{Name: "id", Required: true},
	}},
	{Verb: "token import", Args: []ArgDefinition{
		{Name: "device", Required: true},
		{Name: "id", Required: true},
	}},
	{Verb: "token remove", Args: []ArgDefinition{
		{Name: "device", Required: true},
		{Name: "id", Required: true},
	}},
	{Verb: "token free", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "token exists", Args: []ArgDefinition{
		{Name: "device", Required: true},
		{Name: "id", Required: true},
	}},
	{Verb: "token count", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "wipe", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "header show", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "header secondary", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "header restore", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
	{Verb: "isluks", Args: []ArgDefinition{
		{Name: "device", Required: true},
	}},
}
