// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Tokens are header metadata that say WHAT opens a keyslot -- a hardware
// authenticator, a TPM, an external agent. A token holds no key material,
// so none of this handles a secret. pkg/luks2 exposes AddToken, SetToken
// and RemoveToken on *Volume, plus (*Header).Tokens() for reading; "free",
// "exists" and "count" are computed from that map here, since the library
// has no dedicated calls for them (DESIGN.md §B.2).

// maxTokenJSONSize bounds a token document this tool will read: the whole
// LUKS2 JSON metadata area is at most a few MiB, and one token is a small
// part of it, so this is generous while still refusing an unbounded read
// of an arbitrary file on a typo.
const maxTokenJSONSize = 64 << 10

func tokenCommand() *command {
	return &command{
		name:     "token",
		synopsis: "Inspect or edit LUKS2 tokens",
		usage: "Usage: luks2 token <subcommand> <device> [id]\n\n" +
			"list <device>            Show every token on the volume\n" +
			"show <device> <id>       Show one token\n" +
			"export <device> <id>     Write one token as JSON\n" +
			"import <device> <id>     Read a token as JSON and store it\n" +
			"remove <device> <id>     Delete a token (the keyslot is NOT touched)\n" +
			"free <device>            Report the first free token slot\n" +
			"exists <device> <id>     Exit 0 if the token is there, 1 if not\n" +
			"count <device>           Report how many tokens there are\n\n" +
			"Options:\n" +
			"  --file <path>          Read (import) or write (export) JSON here; \"-\" is stdin/stdout\n",
		sub: map[string]*command{
			"list":   {name: "token list", synopsis: "Show every token on the volume", usage: "Usage: luks2 token list <device>\n", run: runTokenList},
			"show":   {name: "token show", synopsis: "Show one token", usage: "Usage: luks2 token show <device> <id>\n", run: runTokenShow},
			"export": {name: "token export", synopsis: "Write one token as JSON", usage: "Usage: luks2 token export <device> <id> [--file <path>]\n", run: runTokenExport},
			"import": {name: "token import", synopsis: "Read a token as JSON and store it", usage: "Usage: luks2 token import <device> <id> --file <path>\n", run: runTokenImport},
			"remove": {name: "token remove", synopsis: "Delete a token", usage: "Usage: luks2 token remove <device> <id>\n", run: runTokenRemove},
			"free":   {name: "token free", synopsis: "Report the first free token slot", usage: "Usage: luks2 token free <device>\n", run: runTokenFree},
			"exists": {name: "token exists", synopsis: "Exit 0 if the token is there, 1 if not", usage: "Usage: luks2 token exists <device> <id>\n", run: runTokenExists},
			"count":  {name: "token count", synopsis: "Report how many tokens there are", usage: "Usage: luks2 token count <device>\n", run: runTokenCount},
		},
	}
}

func runTokenList(ctx context.Context, e *env, args []string) error {
	if len(args) < 1 {
		return &UsageError{Command: "token list", Detail: "want <device>"}
	}
	device, err := absPath("token list", args[0])
	if err != nil {
		return err
	}

	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	hdr, err := v.Header(ctx)
	if err != nil {
		return err
	}
	tokens := hdr.Tokens()
	if len(tokens) == 0 {
		_, _ = fmt.Fprintf(e.stdout, "%s has no tokens.\n", device)
		return nil
	}

	// Sorted, because ranging a map is a different order on every call and
	// a listing an operator compares between runs must not shuffle itself.
	ids := make([]int, 0, len(tokens))
	for id := range tokens {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	_, _ = fmt.Fprintln(e.stdout, "Slot  Type                 Keyslots")
	for _, id := range ids {
		t := tokens[id]
		_, _ = fmt.Fprintf(e.stdout, "%-5d %-20s %v\n", id, t.Type, t.Keyslots)
	}
	return nil
}

func runTokenShow(ctx context.Context, e *env, args []string) error {
	_, _, token, err := readOneToken(ctx, "token show", args)
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(e.stdout, "%s\n", encoded)
	return nil
}

func runTokenExport(ctx context.Context, e *env, args []string) error {
	f := newFlags("token export")
	file := f.String("file", "")
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	_, id, token, err := readOneToken(ctx, "token export", positional)
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}

	if *file == "" || *file == stdinKeyFile {
		_, _ = fmt.Fprintf(e.stdout, "%s\n", encoded)
		return nil
	}

	out, err := os.Create(*file) // #nosec G304 -- the operator's own --file argument
	if err != nil {
		return err
	}
	if _, err := out.Write(append(encoded, '\n')); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "Token %d written to %s\n", id, *file)
	return nil
}

// readOneToken opens device read-only and returns the token named by
// args[1], the shared first step of show and export.
func readOneToken(ctx context.Context, command string, args []string) (string, int, luks2.Token, error) {
	device, id, err := tokenDeviceAndID(command, args)
	if err != nil {
		return "", 0, luks2.Token{}, err
	}

	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		return "", 0, luks2.Token{}, err
	}
	defer func() { _ = v.Close() }()

	hdr, err := v.Header(ctx)
	if err != nil {
		return "", 0, luks2.Token{}, err
	}
	token, ok := hdr.Tokens()[id]
	if !ok {
		return "", 0, luks2.Token{}, &errs.Error{Kind: luks2.ErrTokenNotFound, Detail: fmt.Sprintf("%s: token %d not found on %s", command, id, device)}
	}
	return device, id, token, nil
}

func runTokenImport(ctx context.Context, e *env, args []string) error {
	f := newFlags("token import")
	file := f.String("file", "")
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	device, id, err := tokenDeviceAndID("token import", positional)
	if err != nil {
		return err
	}
	if *file == "" {
		return &UsageError{Command: "token import", Detail: `--file is required; use "-" to read the JSON from standard input`}
	}

	var encoded []byte
	if *file == stdinKeyFile {
		encoded, err = readBounded(e.stdin, maxTokenJSONSize)
	} else {
		encoded, err = readFileBounded(*file, maxTokenJSONSize)
	}
	if err != nil {
		return err
	}

	var token luks2.Token
	if err := json.Unmarshal(encoded, &token); err != nil {
		return &UsageError{Command: "token import", Detail: fmt.Sprintf("invalid token JSON: %v", err)}
	}

	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	if err := v.SetToken(ctx, id, token); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "Token %d stored on %s\n", id, device)
	return nil
}

func runTokenRemove(ctx context.Context, e *env, args []string) error {
	device, id, err := tokenDeviceAndID("token remove", args)
	if err != nil {
		return err
	}

	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	if err := v.RemoveToken(ctx, id); err != nil {
		return err
	}

	// Said explicitly, because it is the thing an operator gets wrong:
	// removing a token does not revoke anything.
	_, _ = fmt.Fprintf(e.stdout, "Token %d removed from %s\n", id, device)
	_, _ = fmt.Fprintln(e.stdout, "The keyslot it named is UNCHANGED and still opens the volume.")
	_, _ = fmt.Fprintln(e.stdout, "Use 'luks2 killslot' to revoke the credential itself.")
	return nil
}

func runTokenFree(ctx context.Context, e *env, args []string) error {
	if len(args) < 1 {
		return &UsageError{Command: "token free", Detail: "want <device>"}
	}
	device, err := absPath("token free", args[0])
	if err != nil {
		return err
	}

	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	hdr, err := v.Header(ctx)
	if err != nil {
		return err
	}
	tokens := hdr.Tokens()

	slot := -1
	for i := 0; i < luks2.MaxTokens; i++ {
		if _, ok := tokens[i]; !ok {
			slot = i
			break
		}
	}
	if slot < 0 {
		return &errs.Error{Kind: luks2.ErrNoSpace, Detail: fmt.Sprintf("no free token slot on %s", device)}
	}

	_, _ = fmt.Fprintf(e.stdout, "%d\n", slot)
	return nil
}

// runTokenExists answers with its EXIT CODE as well as its output, so a
// script can branch on it without parsing anything.
func runTokenExists(ctx context.Context, e *env, args []string) error {
	device, id, err := tokenDeviceAndID("token exists", args)
	if err != nil {
		return err
	}

	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	hdr, err := v.Header(ctx)
	if err != nil {
		return err
	}
	if _, ok := hdr.Tokens()[id]; !ok {
		_, _ = fmt.Fprintf(e.stdout, "Token %d is not present on %s\n", id, device)
		return &errs.Error{Kind: luks2.ErrTokenNotFound, Detail: fmt.Sprintf("token %d not present on %s", id, device)}
	}

	_, _ = fmt.Fprintf(e.stdout, "Token %d is present on %s\n", id, device)
	return nil
}

func runTokenCount(ctx context.Context, e *env, args []string) error {
	if len(args) < 1 {
		return &UsageError{Command: "token count", Detail: "want <device>"}
	}
	device, err := absPath("token count", args[0])
	if err != nil {
		return err
	}

	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	hdr, err := v.Header(ctx)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "%d\n", len(hdr.Tokens()))
	return nil
}

// tokenDeviceAndID parses the <device> <id> pair every single-token
// subcommand takes.
func tokenDeviceAndID(command string, args []string) (string, int, error) {
	if len(args) < 2 {
		return "", 0, &UsageError{Command: command, Detail: "want <device> <id>"}
	}
	device, err := absPath(command, args[0])
	if err != nil {
		return "", 0, err
	}
	id, err := parseTokenID(command, args[1])
	if err != nil {
		return "", 0, err
	}
	return device, id, nil
}

// parseTokenID converts an operator's token argument, refusing anything
// that is not a slot this container can have.
func parseTokenID(command, arg string) (int, error) {
	id, err := strconv.Atoi(arg)
	if err != nil {
		return 0, &UsageError{Command: command, Detail: fmt.Sprintf("%q is not a token id", arg)}
	}
	if id < 0 || id >= luks2.MaxTokens {
		return 0, &UsageError{Command: command, Detail: fmt.Sprintf("token %d is out of range (0-%d)", id, luks2.MaxTokens-1)}
	}
	return id, nil
}

// readBounded reads r fully, refusing anything over limit. Token JSON
// holds no key material, so this is an ordinary byte slice, not an
// enclave.
func readBounded(r io.Reader, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("input exceeds %d bytes", limit)}
	}
	return data, nil
}

func readFileBounded(path string, limit int) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's own --file argument
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readBounded(f, limit)
}
