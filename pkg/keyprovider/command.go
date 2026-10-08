// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package keyprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/command"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/secret"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// maxHelperOutput bounds how much of a helper's stdout is read into LOCKED
// memory.
//
// The protocols here produce six short lines. 64 KiB is far above that and far
// below the point where a locked allocation -- a process-wide rlimited
// resource -- becomes a way for a misbehaving helper to fail every other
// operation in flight. See internal/secret's ErrProtectedMemory discussion of
// RLIMIT_MEMLOCK.
const maxHelperOutput = 64 << 10

// maxHelperStderr bounds how much of a helper's stderr is kept for the error
// message. Diagnostics from these helpers are one line; the bound exists so a
// helper that writes forever cannot grow this process's memory through a
// failure path.
const maxHelperStderr = 4 << 10

// expiredDeadline is a read deadline already in the past: setting it makes a
// blocked read return at once, without consulting a clock.
var expiredDeadline = time.Unix(1, 0)

// Command runs a program and takes its standard output as the credential.
//
// # Where the output goes
//
// The helper's stdout is read DIRECTLY INTO LOCKED MEMORY -- the pipe is
// drained into the pages of an enclave rather than into a heap buffer that
// io.Copy would have to be trusted to release. Material that touches the
// ordinary heap can be swapped or core-dumped before anything gets a chance
// to wipe it.
//
// # Line, and the trailing newline
//
// WithLine selects which 1-based line of stdout is the credential, and the
// line TERMINATOR IS NOT PART OF IT. That is what the helper protocols need:
// fido2-assert writes six newline-separated fields and the secret is the
// sixth.
//
// Line 0 (the default) takes the whole of stdout VERBATIM, newline and all.
// That is deliberate and matches `cryptsetup --key-file`: a helper that emits
// a passphrase controls its own bytes, and silently trimming them is the
// classic way a credential works one way and not the other.
type Command struct {
	path  string
	args  []string
	stdin []byte
	line  int
	env   []string
	token luks2.Token

	sys commandSys
}

// commandSys is this package's seam: the production environment a Command
// runs its helper with, read once at construction (DESIGN.md §E).
type commandSys struct {
	// env is the helper's base environment, over the fixed system
	// directories: a helper does NOT inherit this process's environment,
	// so a variable the invoking user set (LD_PRELOAD, a PATH entry they
	// control) cannot reach the program that produces the credential.
	env []string

	// waitDelay bounds how long a helper's output is waited for once the
	// helper itself has exited, or after ctx ends and it has been killed.
	waitDelay time.Duration

	// clock is where the post-exit wait gets its timer, so a test can
	// shorten it without a real sleep.
	clock clock.Clock
}

func defaultCommandSys() commandSys {
	return commandSys{
		env:       command.System().Env,
		waitDelay: 2 * time.Second,
		clock:     clock.System{},
	}
}

// CommandOption configures a Command at construction.
type CommandOption func(*Command)

// WithArgs sets the helper's arguments, not including the program name.
func WithArgs(args ...string) CommandOption {
	return func(c *Command) { c.args = append([]string(nil), args...) }
}

// WithStdin sets what is fed to the helper. The FIDO2 protocols pass their
// parameters this way.
//
// Stdin is for NON-SECRET helper input only. The bytes are copied into
// ordinary memory that is never wiped, so a credential passed through it would
// sit in an unwipeable buffer (internal/secret/doc.go lists this boundary).
func WithStdin(b []byte) CommandOption {
	return func(c *Command) { c.stdin = append([]byte(nil), b...) }
}

// WithLine sets the 1-based line of stdout to take. 0, the default, takes
// all of it.
func WithLine(n int) CommandOption {
	return func(c *Command) { c.line = n }
}

// WithEnv sets extra environment for the helper, as NAME=value entries,
// added to the fixed base environment every Command runs with.
func WithEnv(kv ...string) CommandOption {
	return func(c *Command) { c.env = append([]string(nil), kv...) }
}

// WithToken sets the token to record for this credential.
func WithToken(t luks2.Token) CommandOption {
	return func(c *Command) { c.token = t }
}

// NewCommand builds a Command that runs path, an ABSOLUTE path to the helper
// binary.
//
// A relative or bare name is refused rather than searched for on PATH: an
// unlock credential must not depend on the environment of whoever happened to
// invoke the process.
func NewCommand(path string, opts ...CommandOption) (*Command, error) {
	const op = "NewCommand"
	if path == "" {
		return nil, errAt(op, path, &errs.Error{Kind: ErrInvalidArgument, Detail: "no helper command configured"})
	}
	if !filepath.IsAbs(path) {
		return nil, errAt(op, path, &errs.Error{Kind: ErrInvalidArgument, Detail: "helper path is not absolute"})
	}

	c := &Command{path: path, sys: defaultCommandSys()}
	for _, opt := range opts {
		opt(c)
	}
	if c.line < 0 {
		return nil, errAt(op, path, &errs.Error{Kind: ErrInvalidArgument, Detail: fmt.Sprintf("line %d is not a line number", c.line)})
	}
	return c, nil
}

var _ luks2.KeyProvider = (*Command)(nil)

// Token returns the metadata for this credential, or the zero Token (empty
// Type) for an anonymous one, per luks2.KeyProvider -- the identifier
// collision DECISIONS.md H10d flagged is resolved in H9d's entry.
func (p *Command) Token() luks2.Token { return p.token }

// Passphrase runs the command and returns the selected output in protected
// memory.
func (p *Command) Passphrase(ctx context.Context) (*enclave.MemoryEnclave, error) {
	const op = "Command.Passphrase"

	out, n, err := p.run(ctx)
	if err != nil {
		return nil, errAt(op, p.path, err)
	}
	defer secret.System().Release(out)

	credential, err := p.selectLine(out, n)
	if err != nil {
		return nil, errAt(op, p.path, err)
	}
	return credential, nil
}

// run executes the helper and returns its stdout in locked memory together
// with the number of bytes actually written.
//
// # Why stdout is an os.Pipe and not StdoutPipe
//
// The read must end when ctx does. A read from StdoutPipe does not: killing
// the helper on cancellation closes nothing if a grandchild inherited its
// stdout, and the read then waits for that grandchild for ever. An os.Pipe is
// this process's own, read through the runtime poller, so a deadline can be
// set on it -- expiredDeadline when ctx ends, and sys.waitDelay after the
// helper exits, for a grandchild that keeps the pipe open with no deadline in
// ctx at all. cmd.WaitDelay does the same for the stderr copy.
func (p *Command) run(ctx context.Context) (*enclave.MemoryEnclave, int, error) {
	const op = "helper output"
	custody := secret.System()

	cmd := exec.CommandContext(ctx, p.path, p.args...) // #nosec G204 -- the helper is an absolute path named by the caller or by a token it authored
	cmd.Env = append(append([]string(nil), p.sys.env...), p.env...)
	cmd.WaitDelay = p.sys.waitDelay
	if len(p.stdin) > 0 {
		cmd.Stdin = bytes.NewReader(p.stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{w: &stderr, remaining: maxHelperStderr}

	stdout, writeEnd, err := os.Pipe()
	if err != nil {
		return nil, 0, &errs.Error{Kind: errs.ErrIO, Detail: op, Err: err}
	}
	defer func() { _ = stdout.Close() }()
	cmd.Stdout = writeEnd

	buf, err := custody.New(op, maxHelperOutput)
	if err != nil {
		_ = writeEnd.Close()
		return nil, 0, err
	}

	startErr := cmd.Start()
	// The child has its own copy now; this one must go, or the read below
	// never sees end-of-file.
	_ = writeEnd.Close()
	if startErr != nil {
		custody.Release(buf)
		return nil, 0, &HelperError{Path: p.path, ExitCode: -1, Kind: ErrHelperFailed, Err: startErr}
	}

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	stop := make(chan struct{})
	watched := make(chan struct{})
	var cut, cutAfterExit bool
	go func() {
		defer close(watched)
		select {
		case <-ctx.Done():
			cut = true
		case <-stop:
			return
		case waitErr := <-exited:
			exited <- waitErr // put back for the reader of the result
			timer := p.sys.clock.NewTimer(p.sys.waitDelay)
			defer timer.Stop()
			select {
			case <-stop:
				return
			case <-ctx.Done():
				cut = true
			case <-timer.C():
				cut, cutAfterExit = true, true
			}
		}
		_ = stdout.SetReadDeadline(expiredDeadline)
	}()

	// Drained INSIDE the borrow so the bytes land in the locked pages and
	// nowhere else. A short read is not an error here -- the helpers write
	// far less than the bound -- but an OVERLONG one is: silently
	// truncating a credential produces one that enrolls and never opens.
	var n int
	readErr := secret.Borrow(op, buf, func(dst []byte) error {
		var err error
		n, err = readFullish(stdout, dst)
		return err
	})
	close(stop)
	<-watched

	// A helper that overran the bound, or whose output was cut off, is
	// STILL RUNNING or still holds the pipe, and nothing will drain it
	// again. With context.Background(), which an unattended unlock at
	// boot typically passes, nothing else would end it: kill it here
	// rather than wait for one that cannot finish. Closing the pipe alone
	// would not stop a helper that ignores EPIPE.
	if readErr != nil {
		_ = stdout.Close() // a writer still blocked on the pipe gets EPIPE
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
	waitErr := <-exited

	switch {
	case cut && ctx.Err() != nil:
		custody.Release(buf)
		return nil, 0, &errs.Error{Kind: ctx.Err(), Detail: p.path + " did not finish", Err: ctx.Err()}
	case cutAfterExit:
		custody.Release(buf)
		return nil, 0, &errs.Error{Kind: ErrHelperOutput,
			Detail: p.path + " exited, but its output was still held open by a process it started"}
	case readErr != nil:
		custody.Release(buf)
		return nil, 0, readErr
	case waitErr != nil:
		custody.Release(buf)
		return nil, 0, &HelperError{
			Path:     p.path,
			ExitCode: exitCodeOf(waitErr),
			Stderr:   stderr.String(),
			Kind:     ErrHelperFailed,
			Err:      waitErr,
		}
	}

	return buf, n, nil
}

// selectLine narrows the helper's output to the configured line, copying it
// into an enclave of exactly the right size.
func (p *Command) selectLine(out *enclave.MemoryEnclave, n int) (*enclave.MemoryEnclave, error) {
	const op = "helper credential"
	custody := secret.System()

	var credential *enclave.MemoryEnclave
	err := secret.Borrow(op, out, func(all []byte) error {
		body := all[:n]
		if p.line > 0 {
			line, ok := nthLine(body, p.line)
			if !ok {
				return &errs.Error{
					Kind: ErrHelperOutput,
					Detail: fmt.Sprintf("%s wrote %d line(s), and the credential is on line %d",
						p.path, countLines(body), p.line),
				}
			}
			body = line
		}
		if len(body) == 0 {
			return &errs.Error{
				Kind:   ErrHelperOutput,
				Detail: fmt.Sprintf("%s produced an empty credential", p.path),
			}
		}

		var err error
		credential, err = custody.Clone(op, body)
		return err
	})
	if err != nil {
		return nil, err
	}

	return credential, nil
}

// readFullish fills dst from r and reports how much arrived, refusing output
// that does not fit rather than truncating it.
func readFullish(r io.Reader, dst []byte) (int, error) {
	n, err := io.ReadFull(r, dst)
	switch {
	case err == nil:
		// dst filled exactly. There may be more behind it, and a credential
		// cut at an arbitrary boundary is the failure this refuses.
		extra := make([]byte, 1)
		if _, peekErr := r.Read(extra); peekErr == nil {
			return 0, &errs.Error{
				Kind:   ErrHelperOutput,
				Detail: fmt.Sprintf("more than %d bytes of output", len(dst)),
			}
		}
		return n, nil
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return n, nil
	default:
		return 0, err
	}
}

// nthLine returns the 1-based nth line of b without its terminator.
//
// A trailing "\r" is stripped with the "\n": the helpers do not emit one, but
// a wrapper script run through a tool that rewrites line endings does, and a
// carriage return glued to a base64 field is a credential that enrolls and
// never opens.
func nthLine(b []byte, n int) ([]byte, bool) {
	for i := 1; ; i++ {
		idx := bytes.IndexByte(b, '\n')
		var line []byte
		if idx < 0 {
			line, b = b, nil
		} else {
			line, b = b[:idx], b[idx+1:]
		}
		if i == n {
			return bytes.TrimSuffix(line, []byte("\r")), true
		}
		if idx < 0 {
			return nil, false
		}
	}
}

// countLines reports how many lines b holds, for error messages only.
func countLines(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	n := bytes.Count(b, []byte("\n"))
	if !bytes.HasSuffix(b, []byte("\n")) {
		n++
	}
	return n
}

// exitCodeOf extracts a process exit status, or -1 when the failure was not
// one.
func exitCodeOf(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// limitedWriter keeps the first n bytes written to it and discards the rest,
// so a helper's diagnostics cannot grow this process without bound.
type limitedWriter struct {
	w         io.Writer
	remaining int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.remaining <= 0 {
		return len(p), nil
	}
	keep := p
	if len(keep) > l.remaining {
		keep = keep[:l.remaining]
	}
	n, err := l.w.Write(keep)
	l.remaining -= n
	if err != nil {
		return n, err
	}
	return len(p), nil
}
