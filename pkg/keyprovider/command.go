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

// maxHelperOutput bounds how much helper stdout is read into locked memory.
const maxHelperOutput = 64 << 10

// maxHelperStderr bounds how much helper stderr is kept for the error message.
const maxHelperStderr = 4 << 10

// expiredDeadline is a read deadline already in the past: setting it makes a
// blocked read return at once, without consulting a clock.
var expiredDeadline = time.Unix(1, 0)

// Command runs a program and reads its stdout into locked memory as the credential: WithLine picks a line without its terminator, line 0 takes stdout verbatim.
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
// runs its helper with, read once at construction (no package-level mutable vars).
type commandSys struct {
	// env is the helper's fixed base environment; it does not inherit this process's.
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

// WithStdin sets non-secret input fed to the helper; the bytes are never wiped.
func WithStdin(b []byte) CommandOption {
	return func(c *Command) { c.stdin = append([]byte(nil), b...) }
}

// WithLine sets the 1-based line of stdout to take. 0, the default, takes
// all of it.
func WithLine(n int) CommandOption {
	return func(c *Command) { c.line = n }
}

// WithEnv adds NAME=value entries to the helper's fixed base environment.
func WithEnv(kv ...string) CommandOption {
	return func(c *Command) { c.env = append([]string(nil), kv...) }
}

// WithToken sets the token to record for this credential.
func WithToken(t luks2.Token) CommandOption {
	return func(c *Command) { c.token = t }
}

// NewCommand builds a Command for the absolute helper path; Passphrase checks the helper as a system tool and runs it from the checked descriptor.
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
// Type) for an anonymous one, per luks2.KeyProvider, which returns a Token
// by value rather than a *Token.
func (p *Command) Token() luks2.Token { return p.token }

// Passphrase runs the command and returns the selected output in protected
// memory.
func (p *Command) Passphrase(ctx context.Context) (enclave.ByteAccess, error) {
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

// run executes the helper and returns its stdout in locked memory with the byte count, reading an os.Pipe whose deadline follows ctx.
func (p *Command) run(ctx context.Context) (enclave.ByteAccess, int, error) {
	const op = "helper output"
	custody := secret.System()

	// The helper gets system-tool trust checks and runs from the checked descriptor.
	prog, err := command.Open(p.path)
	if err != nil {
		return nil, 0, &errs.Error{Kind: ErrHelperFailed, Detail: "the helper is not trusted", Err: err}
	}
	defer func() { _ = prog.Close() }()
	cmd := prog.Cmd(ctx, p.args...)
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

	// Drain inside the borrow; an overlong read is an error, never truncated.
	var n int
	readErr := secret.Borrow(op, buf, func(dst []byte) error {
		var err error
		n, err = readFullish(stdout, dst)
		return err
	})
	close(stop)
	<-watched

	// Kill a helper that overran or still holds the pipe; nothing else would end it.
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
func (p *Command) selectLine(out enclave.ByteAccess, n int) (enclave.ByteAccess, error) {
	const op = "helper credential"
	custody := secret.System()

	var credential enclave.ByteAccess
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

// nthLine returns the 1-based nth line of b without its \n or \r\n terminator.
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
