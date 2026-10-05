// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Tokens: the header metadata that says WHAT opens a keyslot -- a hardware
// authenticator, a TPM, an external agent.
//
// A token holds no key material. It is the record that lets an implementation
// find the credential for a keyslot, which is why it can be exported, edited
// and imported as plain JSON without any of this handling a secret.

// tokenUsage is the group's own help.
func (c *CLI) tokenUsage() int {
	_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 token <subcommand> <device> [id]")
	_, _ = fmt.Fprintln(c.Stdout, "")
	_, _ = fmt.Fprintln(c.Stdout, "Subcommands:")
	_, _ = fmt.Fprintln(c.Stdout, "  list <device>            Show every token on the volume")
	_, _ = fmt.Fprintln(c.Stdout, "  show <device> <id>       Show one token")
	_, _ = fmt.Fprintln(c.Stdout, "  export <device> <id>     Write one token as JSON")
	_, _ = fmt.Fprintln(c.Stdout, "  import <device> <id>     Read a token as JSON and store it")
	_, _ = fmt.Fprintln(c.Stdout, "  remove <device> <id>     Delete a token (the keyslot is NOT touched)")
	_, _ = fmt.Fprintln(c.Stdout, "  free <device>            Report the first free token slot")
	_, _ = fmt.Fprintln(c.Stdout, "  exists <device> <id>     Exit 0 if the token is there, 1 if not")
	_, _ = fmt.Fprintln(c.Stdout, "  count <device>           Report how many tokens there are")
	_, _ = fmt.Fprintln(c.Stdout, "")
	_, _ = fmt.Fprintln(c.Stdout, "Options:")
	_, _ = fmt.Fprintln(c.Stdout, "  --file <path>            Read (import) or write (export) JSON here; \"-\" is stdin/stdout")
	_, _ = fmt.Fprintln(c.Stdout, "")
	_, _ = fmt.Fprintln(c.Stdout, "Examples:")
	_, _ = fmt.Fprintln(c.Stdout, "  luks2 token list /dev/sdb1")
	_, _ = fmt.Fprintln(c.Stdout, "  luks2 token export /dev/sdb1 0 --file token0.json")
	_, _ = fmt.Fprintln(c.Stdout, "  luks2 token import /dev/sdb1 0 --file token0.json")
	return 1
}

// cmdToken dispatches the token subcommands.
func (c *CLI) cmdToken() int {
	if len(c.Args) < 3 {
		return c.tokenUsage()
	}

	o := newOptions("token " + c.Args[2])
	file := o.String("file", "")
	args, err := o.parse(c.Args[3:])
	if err != nil {
		return c.usageError(err)
	}

	sub := c.Args[2]
	if len(args) < 1 {
		return c.tokenUsage()
	}
	device, err := absPath("token "+c.Args[2], args[0])
	if err != nil {
		return c.usageError(err)
	}

	// The subcommands that address a single token all take the id the same way,
	// so it is parsed once rather than five times.
	tokenID := -1
	switch sub {
	case "show", "export", "import", "remove", "exists":
		if len(args) < 2 {
			return c.tokenUsage()
		}
		tokenID, err = parseTokenID(sub, args[1])
		if err != nil {
			return c.usageError(err)
		}
	}

	switch sub {
	case "list":
		return c.cmdTokenList(device)
	case "show":
		return c.cmdTokenShow(device, tokenID)
	case "export":
		return c.cmdTokenExport(device, tokenID, *file)
	case "import":
		return c.cmdTokenImport(device, tokenID, *file)
	case "remove":
		return c.cmdTokenRemove(device, tokenID)
	case "free":
		return c.cmdTokenFree(device)
	case "exists":
		return c.cmdTokenExists(device, tokenID)
	case "count":
		return c.cmdTokenCount(device)
	default:
		_, _ = fmt.Fprintf(c.Stderr, "Unknown token subcommand: %s\n\n", sub)
		return c.tokenUsage()
	}
}

func (c *CLI) cmdTokenList(device string) int {
	tokens, err := c.Luks.ListTokens(device)
	if err != nil {
		return c.fail(err)
	}
	if len(tokens) == 0 {
		_, _ = fmt.Fprintf(c.Stdout, "%s has no tokens.\n", device)
		return 0
	}

	// Sorted, because ranging a map is a different order on every call and a
	// listing an operator compares between runs must not shuffle itself.
	ids := make([]int, 0, len(tokens))
	for id := range tokens {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	_, _ = fmt.Fprintln(c.Stdout, "Slot  Type                 Keyslots")
	for _, id := range ids {
		t := tokens[id]
		_, _ = fmt.Fprintf(c.Stdout, "%-5d %-20s %v\n", id, t.Type, t.Keyslots)
	}
	return 0
}

func (c *CLI) cmdTokenShow(device string, tokenID int) int {
	token, err := c.Luks.GetToken(device, tokenID)
	if err != nil {
		return c.fail(err)
	}

	encoded, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return c.fail(err)
	}

	_, _ = fmt.Fprintf(c.Stdout, "%s\n", encoded)
	return 0
}

// cmdTokenExport writes a token's JSON, to a file or to stdout.
func (c *CLI) cmdTokenExport(device string, tokenID int, file string) int {
	encoded, err := c.Luks.ExportToken(device, tokenID)
	if err != nil {
		return c.fail(err)
	}

	if file == "" || file == stdinKeyFile {
		_, _ = fmt.Fprintf(c.Stdout, "%s\n", encoded)
		return 0
	}

	f, err := c.FS.Create(file)
	if err != nil {
		return c.fail(err)
	}
	if _, err := f.Write(append(encoded, '\n')); err != nil {
		_ = f.Close()
		return c.fail(err)
	}
	if err := f.Close(); err != nil {
		return c.fail(err)
	}

	_, _ = fmt.Fprintf(c.Stdout, "Token %d written to %s\n", tokenID, file)
	return 0
}

// cmdTokenImport stores a token given as JSON.
//
// It goes through ImportTokenJSON rather than building a Token here, so that
// the parse and the validation happen in the library where the header rules
// live: a CLI that assembled the struct itself would be a second place that has
// to know what a valid token is.
func (c *CLI) cmdTokenImport(device string, tokenID int, file string) int {
	if file == "" {
		return c.usageError(&UsageError{
			Command: "token import",
			Detail:  "--file is required; use \"-\" to read the JSON from standard input",
		})
	}

	var (
		encoded []byte
		err     error
	)
	if file == stdinKeyFile {
		encoded, err = readAllSecret(c.Stdin, maxTokenJSONSize)
	} else {
		encoded, err = c.readFile(file, maxTokenJSONSize)
	}
	if err != nil {
		return c.fail(err)
	}

	if err := c.Luks.ImportTokenJSON(device, tokenID, encoded); err != nil {
		return c.fail(err)
	}

	_, _ = fmt.Fprintf(c.Stdout, "Token %d stored on %s\n", tokenID, device)
	return 0
}

// cmdTokenRemove deletes a token.
func (c *CLI) cmdTokenRemove(device string, tokenID int) int {
	if err := c.Luks.RemoveToken(device, tokenID); err != nil {
		return c.fail(err)
	}

	// Said explicitly, because it is the thing an operator gets wrong: removing
	// a token does not revoke anything. The credential still opens the volume;
	// what is gone is the record of what that credential is.
	_, _ = fmt.Fprintf(c.Stdout, "Token %d removed from %s\n", tokenID, device)
	_, _ = fmt.Fprintln(c.Stdout, "The keyslot it named is UNCHANGED and still opens the volume.")
	_, _ = fmt.Fprintln(c.Stdout, "Use 'luks2 killslot' to revoke the credential itself.")
	return 0
}

func (c *CLI) cmdTokenFree(device string) int {
	slot, err := c.Luks.FindFreeTokenSlot(device)
	if err != nil {
		return c.fail(err)
	}

	_, _ = fmt.Fprintf(c.Stdout, "%d\n", slot)
	return 0
}

// cmdTokenExists answers with its EXIT CODE as well as its output, so a script
// can branch on it without parsing anything.
func (c *CLI) cmdTokenExists(device string, tokenID int) int {
	exists, err := c.Luks.TokenExists(device, tokenID)
	if err != nil {
		return c.fail(err)
	}
	if !exists {
		_, _ = fmt.Fprintf(c.Stdout, "Token %d is not present on %s\n", tokenID, device)
		return 1
	}

	_, _ = fmt.Fprintf(c.Stdout, "Token %d is present on %s\n", tokenID, device)
	return 0
}

func (c *CLI) cmdTokenCount(device string) int {
	count, err := c.Luks.CountTokens(device)
	if err != nil {
		return c.fail(err)
	}

	_, _ = fmt.Fprintf(c.Stdout, "%d\n", count)
	return 0
}

// maxTokenJSONSize bounds a token document this tool will read.
//
// The whole LUKS2 JSON metadata area is at most 4 MiB and one token is a small
// part of it, so 64 KiB is generous. The bound exists because the path comes
// from the operator and an unbounded read of an arbitrary file is how a tool
// exhausts memory on a typo.
const maxTokenJSONSize = 64 << 10

// readFile reads a bounded file through the FileSystem seam.
func (c *CLI) readFile(path string, limit int) ([]byte, error) {
	f, err := c.FS.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return readAllSecret(f, limit)
}

// parseTokenID converts an operator's token argument, refusing anything that is
// not a slot this container can have.
func parseTokenID(command, arg string) (int, error) {
	id, err := strconv.Atoi(arg)
	if err != nil {
		return 0, &UsageError{Command: command, Detail: fmt.Sprintf("%q is not a token id", arg)}
	}
	if id < 0 || id >= luks2.MaxTokenSlots {
		return 0, &UsageError{
			Command: command,
			Detail:  fmt.Sprintf("token %d is out of range (0-%d)", id, luks2.MaxTokenSlots-1),
		}
	}
	return id, nil
}
