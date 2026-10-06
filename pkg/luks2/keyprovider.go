// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// External key providers: credentials that come from something outside this
// process -- a hardware authenticator, an agent, a script -- rather than from a
// human at a terminal.
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
// here: run a command, take a line of its output. CommandKeyProvider is that
// mechanism, and the FIDO2 provider is a configuration of it rather than a
// second implementation. A TPM helper, a network agent or a smartcard script
// needs no new code in this package.

// KeyProvider yields a volume credential from outside this process, together
// with the token that records where it came from.
//
// The credential is returned in protected memory and is the CALLER's to
// Destroy. Token returns the metadata to write into the LUKS2 header alongside
// the keyslot; its Keyslots field is filled in by EnrollKeyProvider, which is
// the only place that knows the answer.
type KeyProvider interface {
	// Passphrase runs whatever produces the credential and returns it. ctx
	// bounds the work: a hardware authenticator waiting for a touch blocks
	// until the user acts, and an unattended unlock needs that to end.
	Passphrase(ctx context.Context) (*enclave.MemoryEnclave, error)

	// Token returns the header metadata identifying this credential, or nil
	// when the provider is anonymous and no token should be written.
	Token() *Token
}

// maxHelperOutput bounds how much of a helper's stdout is read into LOCKED
// memory.
//
// The protocols here produce six short lines. 64 KiB is far above that and far
// below the point where a locked allocation -- a process-wide rlimited
// resource -- becomes a way for a misbehaving helper to fail every other
// operation in flight. See the RLIMIT_MEMLOCK discussion on ErrProtectedMemory.
const maxHelperOutput = 64 << 10

// maxHelperStderr bounds how much of a helper's stderr is kept for the error
// message. Diagnostics from these helpers are one line; the bound exists so a
// helper that writes forever cannot grow this process's memory through a
// failure path.
const maxHelperStderr = 4 << 10

// CommandKeyProvider runs a command and takes its standard output as the
// credential.
//
// # Where the output goes
//
// The helper's stdout is read DIRECTLY INTO LOCKED MEMORY -- the pipe is drained
// into the pages of an enclave rather than into a heap buffer that io.Copy would
// have to be trusted to release. It is the same reason custody.Random draws into
// locked pages instead of moving bytes afterwards: material that touches the
// ordinary heap can be swapped or core-dumped before anything gets a chance to
// wipe it.
//
// # Line, and the trailing newline
//
// Line selects which 1-based line of stdout is the credential, and the line
// TERMINATOR IS NOT PART OF IT. That is what the helper protocols need:
// fido2-assert writes six newline-separated fields and the secret is the sixth.
//
// Line == 0 takes the whole of stdout VERBATIM, newline and all. That is
// deliberate and matches `cryptsetup --key-file`: a helper that emits a
// passphrase controls its own bytes, and silently trimming them is the classic
// way a credential works one way and not the other.
type CommandKeyProvider struct {
	// Path is the helper binary, as an ABSOLUTE path. A relative or bare name
	// is refused rather than searched for on PATH: an unlock credential must
	// not depend on the environment of whoever happened to invoke the process.
	Path string

	// Args are the helper's arguments, not including the program name.
	Args []string

	// Stdin is fed to the helper. The FIDO2 protocols pass their parameters
	// this way.
	Stdin []byte

	// Line is the 1-based line of stdout to take, or 0 for all of it.
	Line int

	// Meta is the token to record for this credential, or nil for none. It is
	// COPIED before anything is written, so a provider can be reused.
	Meta *Token

	// Env is extra environment for the helper, as NAME=value entries. The
	// helper does NOT inherit this process's environment: it gets
	// helperBaseEnv plus these, and nothing else, so a variable the invoking
	// user set (LD_PRELOAD, a PATH entry they control, a library's debug hook)
	// cannot reach the program that produces the credential.
	Env []string
}

// helperBaseEnv is the whole environment a helper gets besides
// CommandKeyProvider.Env: a PATH of system directories only, for a helper
// script that runs other tools.
var helperBaseEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}

// helperWaitDelay bounds how long a helper's output is waited for once the
// helper itself has exited, or after ctx ends and it has been killed. A
// grandchild that inherited the helper's stdout or stderr and kept it open
// would otherwise hold the read, and Wait, forever. A variable so tests need
// not wait it out.
var helperWaitDelay = 2 * time.Second

// expiredDeadline is a read deadline already in the past: setting it makes a
// blocked read return at once, without consulting a clock.
var expiredDeadline = time.Unix(1, 0)

// Ensure CommandKeyProvider satisfies the interface at compile time.
var _ KeyProvider = (*CommandKeyProvider)(nil)

// Token returns the metadata for this credential.
func (p *CommandKeyProvider) Token() *Token {
	return p.Meta
}

// Passphrase runs the command and returns the selected output in protected
// memory.
func (p *CommandKeyProvider) Passphrase(ctx context.Context) (*enclave.MemoryEnclave, error) {
	if p.Path == "" {
		return nil, &KeyProviderError{Op: "command key provider", Err: ErrHelperNotConfigured}
	}
	if !filepath.IsAbs(p.Path) {
		return nil, &KeyProviderError{Op: "command key provider", Err: &errs.Error{Kind: ErrHelperPathNotAbsolute, Detail: strconv.Quote(p.Path)}}
	}
	if p.Line < 0 {
		return nil, &KeyProviderError{
			Op: "command key provider",
			Err: &errs.Error{
				Kind:   ErrHelperOutput,
				Detail: fmt.Sprintf("line %d is not a line number", p.Line),
			},
		}
	}

	out, n, err := p.run(ctx)
	if err != nil {
		return nil, err
	}
	defer custody.Release(out)

	return p.selectLine(out, n)
}

// run executes the helper and returns its stdout in locked memory together with
// the number of bytes actually written.
//
// # Why stdout is an os.Pipe and not StdoutPipe
//
// The read must end when ctx does. A read from StdoutPipe does not: killing
// the helper on cancellation closes nothing if a grandchild inherited its
// stdout, and the read then waits for that grandchild for ever. An os.Pipe is
// this process's own, read through the runtime poller, so a deadline can be
// set on it -- expiredDeadline when ctx ends, and helperWaitDelay after the
// helper exits, for a grandchild that keeps the pipe open with no deadline in
// ctx at all. cmd.WaitDelay does the same for the stderr copy.
func (p *CommandKeyProvider) run(ctx context.Context) (*enclave.MemoryEnclave, int, error) {
	op := "helper output"

	cmd := exec.CommandContext(ctx, p.Path, p.Args...) // #nosec G204 -- the helper is an absolute path named by the caller or by a token it authored
	cmd.Env = append(append([]string(nil), helperBaseEnv...), p.Env...)
	cmd.WaitDelay = helperWaitDelay
	if len(p.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(p.Stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{w: &stderr, remaining: maxHelperStderr}

	stdout, writeEnd, err := os.Pipe()
	if err != nil {
		return nil, 0, &KeyProviderError{Op: op, Err: err}
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
		return nil, 0, &HelperError{Path: p.Path, ExitCode: -1, Err: startErr}
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
			select {
			case <-stop:
				return
			case <-ctx.Done():
				cut = true
			case <-time.After(helperWaitDelay):
				cut, cutAfterExit = true, true
			}
		}
		_ = stdout.SetReadDeadline(expiredDeadline)
	}()

	// Drained INSIDE the borrow so the bytes land in the locked pages and
	// nowhere else. A short read is not an error here -- the helpers write far
	// less than the bound -- but an OVERLONG one is: silently truncating a
	// credential produces one that enrolls and never opens.
	var n int
	readErr := secret.Borrow(op, buf, func(dst []byte) error {
		var err error
		n, err = readFullish(stdout, dst)
		return err
	})
	close(stop)
	<-watched

	// A helper that overran the bound, or whose output was cut off, is STILL
	// RUNNING or still holds the pipe, and nothing will drain it again. With
	// context.Background(), which an unattended unlock at boot typically
	// passes, nothing else would end it: kill it here rather than wait for one
	// that cannot finish. Closing the pipe alone would not stop a helper that
	// ignores EPIPE.
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
		return nil, 0, &KeyProviderError{Op: op, Err: &errs.Error{Detail: p.Path + " did not finish", Err: ctx.Err()}}
	case cutAfterExit:
		custody.Release(buf)
		return nil, 0, &KeyProviderError{Op: op, Err: &errs.Error{Kind: ErrHelperOutput,
			Detail: p.Path + " exited, but its output was still held open by a process it started"}}
	case readErr != nil:
		custody.Release(buf)
		return nil, 0, &KeyProviderError{Op: op, Err: readErr}
	case waitErr != nil:
		custody.Release(buf)
		return nil, 0, &HelperError{
			Path:     p.Path,
			ExitCode: exitCodeOf(waitErr),
			Stderr:   stderr.String(),
			Err:      &errs.Error{Kind: ErrHelperFailed, Err: waitErr},
		}
	}

	return buf, n, nil
}

// selectLine narrows the helper's output to the configured line, copying it into
// an enclave of exactly the right size.
func (p *CommandKeyProvider) selectLine(out *enclave.MemoryEnclave, n int) (*enclave.MemoryEnclave, error) {
	op := "helper credential"

	var credential *enclave.MemoryEnclave
	err := secret.Borrow(op, out, func(all []byte) error {
		body := all[:n]
		if p.Line > 0 {
			line, ok := nthLine(body, p.Line)
			if !ok {
				return &KeyProviderError{
					Op: op,
					Err: &errs.Error{
						Kind: ErrHelperOutput,
						Detail: fmt.Sprintf("%s wrote %d line(s), and the credential is on line %d",
							p.Path, countLines(body), p.Line),
					},
				}
			}
			body = line
		}
		if len(body) == 0 {
			return &KeyProviderError{
				Op: op,
				Err: &errs.Error{
					Kind:   ErrHelperOutput,
					Detail: fmt.Sprintf("%s produced an empty credential", p.Path),
				},
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
		// dst filled exactly. There may be more behind it, and a credential cut
		// at an arbitrary boundary is the failure this refuses.
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
// A trailing "\r" is stripped with the "\n": the helpers do not emit one, but a
// wrapper script run through a tool that rewrites line endings does, and a
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

// exitCodeOf extracts a process exit status, or -1 when the failure was not one.
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

// EnrollKeyProvider adds a provider's credential to a volume and records the
// token that identifies it.
//
// existing is a credential that already opens the volume; it is needed because
// adding a keyslot means unwrapping the master key. The keyslot, the token and
// the rollback that ties them together are enrollWithToken's, which
// AddRecoveryKey uses too.
func EnrollKeyProvider(ctx context.Context, device string, existing []byte, p KeyProvider, opts *AddKeyOptions) (keyslot, tokenID int, err error) {
	if p == nil {
		return -1, -1, &KeyProviderError{Op: "enroll", Err: ErrNoKeyProvider}
	}

	credential, err := p.Passphrase(ctx)
	if err != nil {
		return -1, -1, err
	}
	defer custody.Release(credential)

	// Seeded to -1 so a borrow that never runs the closure reports "no slot"
	// rather than slot 0, which on almost every volume is somebody's primary
	// passphrase.
	keyslot, tokenID = -1, -1

	// enrollWithToken's slot number is carried out ON THE ERROR PATH TOO. The
	// one error that reports a real slot is OrphanedKeyslotError, and that
	// number is the only record of a live credential nothing describes --
	// dropping it here would leave the caller unable to say which slot to
	// remove.
	err = secret.Borrow("provider credential", credential, func(raw []byte) error {
		var inner error
		// callerSuppliedCredential, deliberately: this secret arrives from an
		// external helper rather than from custody.Random here, so it keeps the
		// full hash-dependent floor -- which is exactly what this path did
		// before the policy became a parameter. The kdf.go rationale names an
		// enrolled provider key as a candidate for the exemption on the grounds
		// that it is also a full-entropy value, and it may well be; granting it
		// is a separate decision about a credential this package did not draw,
		// and is not made here as a side effect of threading the parameter
		// through.
		keyslot, tokenID, _, inner = enrollWithToken(device, existing, raw, opts, p.Token(), callerSuppliedCredential)
		return inner
	})
	if err != nil {
		return keyslot, tokenID, err
	}

	return keyslot, tokenID, nil
}

// enrollWithToken adds a credential to a volume and records the token that
// identifies the keyslot it went into.
//
// It is shared by EnrollKeyProvider and AddRecoveryKey because the sequence is
// the same for both and getting it wrong has the same consequence either way.
// token may be nil, for a credential that is not to be described on the device;
// its Keyslots field is filled in here, which is the only place that knows the
// answer.
//
// # Order, and why the keyslot is rolled back
//
// The keyslot is written FIRST because writing it is what produces the slot
// number the token has to name, and the slot number is read from where AddKey
// CHOOSES it rather than inferred from the header afterwards. Inferring it is
// #42: the two rules -- "first free slot" and "the highest-numbered slot
// present" -- agree only while the active slots are contiguous from zero, and a
// wrong answer here is written into a header that outlives the process.
//
// If the token write then fails, the keyslot is REMOVED. A keyslot with no
// token is an orphan: it opens the volume, nothing on the device says what
// opens it, and no operator inspecting the container later can tell it from a
// credential they are still using. When the rollback itself fails the caller
// gets an OrphanedKeyslotError naming the slot, because at that point the only
// remedy is a human with the device.
// policy is the keyslot cost policy the new keyslot is written under. It is a
// parameter rather than a constant because the two callers differ: a recovery
// key is bytes THIS PACKAGE drew, while a key provider's secret arrives from
// outside it. See keyslotCostPolicy (kdf.go).
func enrollWithToken(device string, existing, credential []byte, opts *AddKeyOptions, token *Token, policy keyslotCostPolicy) (keyslot, tokenID int, volumeUUID string, err error) {
	if err := addKeyPreflight(device, existing, credential, opts); err != nil {
		return -1, -1, "", &KeyProviderError{Op: "enroll", Err: err}
	}

	// ONE LOCK, held from the choice of token slot to the token's write (#246
	// D8). The token slot used to be chosen before the keyslot was written,
	// and each step took the device lock on its own, so two enrollments
	// running at once both found the same slot free and the second token
	// overwrote the first: one keyslot was left with no token naming it. Under
	// a single lock the slot chosen is still free when the token is written.
	// The locked descriptor carries every read and write below (#249, A10).
	lock, dev, err := lockKeyslotDevice(device)
	if err != nil {
		return -1, -1, "", &KeyProviderError{Op: "enroll", Err: err}
	}
	defer func() { _ = lock.Release() }()

	// The token slot is chosen BEFORE the keyslot is written: finding no free
	// token slot here costs nothing, while finding it afterwards costs a
	// rollback of live key material.
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return -1, -1, "", &KeyProviderError{Op: "enroll", Err: &errs.Error{Detail: "failed to read header", Err: err}}
	}
	tokenID = -1
	if token != nil {
		if tokenID, err = freeTokenSlot(metadata); err != nil {
			return -1, -1, "", &KeyProviderError{Op: "enroll", Err: err}
		}
	}

	// The VOLUME key: a credential that opens only an unbound keyslot proves
	// nothing about the volume (#249, A1).
	masterKey, _, err := getVolumeKey(dev.file, device, existing, metadata)
	if err != nil {
		return -1, -1, "", &KeyProviderError{Op: "enroll", Err: &errs.Error{Detail: "failed to unlock with existing passphrase", Err: err}}
	}
	defer custody.Release(masterKey)

	// The slot is the one addKeyslotWithMasterKey CHOSE, reported from the
	// point of decision under the device lock, so the token below names the
	// keyslot the credential actually went to rather than one inferred
	// afterwards (#42).
	assignedSlot, err := addKeyslotWithMasterKey(dev, hdr, metadata, masterKey, credential, opts, policy)
	if err != nil {
		return -1, -1, "", &KeyProviderError{Op: "enroll", Err: err}
	}
	if assignedSlot < 0 {
		// Unreachable: addKeyslotWithMasterKey returns a slot on every path
		// that succeeds. Refused rather than reported, because this number's
		// only use is telling an operator which credential is which.
		return -1, -1, "", &KeyProviderError{
			Op:  "enroll",
			Err: &errs.Error{Kind: ErrInvalidKeyslot, Detail: "the credential was written but the keyslot it went to was not reported"},
		}
	}

	// The UUID of the volume the credential went to, from the header read
	// through the locked descriptor: a caller that reopened the path to ask
	// could be told about a different volume (the recovery key file names it).
	volumeUUID = string(bytes.TrimRight(hdr.UUID[:], "\x00"))

	if token == nil {
		return assignedSlot, -1, volumeUUID, nil
	}

	// A COPY, so enrolling the same provider twice does not accumulate keyslot
	// references on the caller's token.
	record := *token
	record.Keyslots = []string{strconv.Itoa(assignedSlot)}

	if err := importToken(dev, tokenID, &record); err != nil {
		if killErr := killKeyslot(dev, assignedSlot); killErr != nil {
			return assignedSlot, -1, "", &OrphanedKeyslotError{Keyslot: assignedSlot, Err: err, Cause: killErr}
		}
		return -1, -1, "", &KeyProviderError{Op: "enroll token", Err: err}
	}

	return assignedSlot, tokenID, volumeUUID, nil
}

// importTokenLocked writes token into slot tokenID for a caller that holds the
// device lock -- ImportToken would wait on that same lock for ever, since
// flock on a second descriptor waits on the first. The slot must still be
// free: it was chosen under this lock, so anything else there is a defect,
// and overwriting it would destroy another credential's record.
//
// It refuses what ImportToken refuses: an id out of range, and a token with no
// type.
func importTokenLocked(dev *keyslotDevice, tokenID int, token *Token) error {
	if tokenID < 0 || tokenID >= MaxTokenSlots {
		return &errs.Error{Kind: ErrInvalidHeader, Detail: "token id " + strconv.Itoa(tokenID) + " is out of range"}
	}
	if token == nil || token.Type == "" {
		return &errs.Error{Kind: ErrUnsupportedTokenType, Detail: "a token must have a type"}
	}
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return err
	}
	if metadata.Tokens == nil {
		metadata.Tokens = make(map[string]*Token)
	}
	key := strconv.Itoa(tokenID)
	if _, taken := metadata.Tokens[key]; taken {
		return &errs.Error{Kind: ErrNoFreeTokenSlot, Detail: "token slot " + key + " was taken while this enrollment held the device lock"}
	}
	metadata.Tokens[key] = token
	hdr.SequenceID++
	return dev.writeHeader(hdr, metadata)
}

// freeTokenSlot returns the lowest token id metadata does not use.
func freeTokenSlot(metadata *LUKS2Metadata) (int, error) {
	for i := 0; i < MaxTokenSlots; i++ {
		if _, used := metadata.Tokens[strconv.Itoa(i)]; !used {
			return i, nil
		}
	}
	return -1, ErrNoFreeTokenSlot
}

// killKeyslotLocked removes a keyslot for a caller that holds the device lock,
// through the same gate every removal takes (removeKeyslotOn).
func killKeyslotLocked(dev *keyslotDevice, keyslot int) error {
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return err
	}
	id := strconv.Itoa(keyslot)
	if _, ok := metadata.Keyslots[id]; !ok {
		return &errs.Error{Kind: ErrInvalidKeyslot, Detail: "keyslot " + id + " does not exist"}
	}
	// Through the pinned descriptor: the rollback must remove the keyslot
	// from the device the enrollment wrote, not whatever the path names now.
	_, err = removeKeyslotOn(dev, hdr, metadata, id)
	return err
}

// importToken is importTokenLocked, reached through a variable so the rollback
// itself can be exercised: the token this package writes for a recovery key is built
// internally and is always well-formed, so there is no argument a test can pass
// that makes the write fail at the point where a keyslot is already on the
// device.
var importToken = importTokenLocked

// killKeyslot is killKeyslotLocked, reached through a variable so the
// rollback's own failure path can be exercised.
//
// Same seam as removeFile in recovery.go and dm in devicemapper.go: what is
// being guarded against is the device refusing a write at exactly one call, and
// a test cannot arrange that any other way. The branch behind it is the only
// one in this file that ends with a human holding a volume that needs
// attention, so it is the last one that should go untested.
var killKeyslot = killKeyslotLocked

// UnlockWithProvider opens a volume with a credential from a provider.
//
// The credential is borrowed for the length of the Unlock call and destroyed
// immediately afterwards, including on the failure path: a hardware assertion
// that did not open the volume is no less sensitive than one that did.
func UnlockWithProvider(ctx context.Context, device, name string, p KeyProvider) error {
	if p == nil {
		return &KeyProviderError{Op: "unlock", Err: ErrNoKeyProvider}
	}

	credential, err := p.Passphrase(ctx)
	if err != nil {
		return err
	}
	defer custody.Release(credential)

	return secret.Borrow("provider credential", credential, func(raw []byte) error {
		return Unlock(device, raw, name)
	})
}

// ProviderFromToken builds the provider a token describes, so a volume can be
// opened from what is recorded on the device rather than from options supplied
// again at unlock time.
//
// A token type this package cannot drive is refused rather than approximated.
func ProviderFromToken(t *Token, exec ExecConfig) (KeyProvider, error) {
	if t == nil {
		return nil, &KeyProviderError{Op: "provider from token", Err: ErrNoKeyProvider}
	}

	switch t.Type {
	case fido2TokenType:
		return fido2ProviderFromToken(t, exec)
	default:
		return nil, &KeyProviderError{
			Op:  "provider from token",
			Err: &errs.Error{Kind: ErrUnsupportedTokenType, Detail: fmt.Sprintf("%q", t.Type)},
		}
	}
}

// ExecConfig names the helper binaries and the authenticator an external
// provider talks to.
//
// The paths are ABSOLUTE and are not looked up on PATH. What unlocks a volume
// must not depend on the environment of whoever invoked the process -- a PATH
// entry a user controls would otherwise be a way to substitute the program that
// produces the credential.
type ExecConfig struct {
	// FIDO2Cred is the fido2-cred binary, used at enrollment.
	FIDO2Cred string

	// FIDO2Assert is the fido2-assert binary, used at unlock.
	FIDO2Assert string

	// Device is the authenticator, as libfido2 names it (a hidraw path on
	// Linux). It is required: the helpers take the device as a mandatory
	// argument and have no default.
	Device string
}

// Default helper locations, used when ExecConfig leaves them unset. These are
// where the libfido2 tools package installs them on Linux.
const (
	DefaultFIDO2CredPath   = "/usr/bin/fido2-cred" // #nosec G101 -- a program path; "cred" here is the fido2-cred binary, not a credential
	DefaultFIDO2AssertPath = "/usr/bin/fido2-assert"
)

func (c ExecConfig) credPath() string {
	if c.FIDO2Cred != "" {
		return c.FIDO2Cred
	}
	return DefaultFIDO2CredPath
}

func (c ExecConfig) assertPath() string {
	if c.FIDO2Assert != "" {
		return c.FIDO2Assert
	}
	return DefaultFIDO2AssertPath
}

// device returns the authenticator, refusing none.
func (c ExecConfig) device() (string, error) {
	if c.Device == "" {
		return "", &KeyProviderError{Op: "fido2 device", Err: ErrNoFIDO2Device}
	}
	return c.Device, nil
}

// ---------------------------------------------------------------------------
// FIDO2
// ---------------------------------------------------------------------------

// The LUKS2 token types this package writes.
//
// They are systemd's spellings, and that is deliberate: a token type is how an
// implementation decides whether it can drive a keyslot at all, so a private
// spelling would produce a container only this library can use -- the opposite
// of what binding a volume to a hardware key, or leaving a recovery key in a
// safe, is for. Both were read out of the systemd-cryptenroll binary on the
// development host (systemd 255) rather than taken from documentation.
//
// They are UNEXPORTED and they are temporary. The exported constants belong in
// types.go beside the Token type, where issue #143 puts them
// (fido2TokenType, TokenTypeSystemdRecovery). That work is on
// issue/143-token-keyslot-passthrough and is NOT on main at the time of
// writing, so declaring exported ones here would collide with it the moment it
// lands. When it does, these two go away and the references below point at
// types.go.
const (
	fido2TokenType    = "systemd-fido2"
	recoveryTokenType = "systemd-recovery"
)

// DefaultFIDO2RelyingParty is the relying-party id systemd-cryptenroll uses.
// Matching it is part of being openable by systemd-cryptsetup.
const DefaultFIDO2RelyingParty = "io.systemd.cryptsetup"

// FIDO2SaltLength is the length of the hmac-secret salt, in bytes. The
// authenticator derives a 32-byte secret from it; 32 is what systemd writes.
const FIDO2SaltLength = 32

// fido2ClientDataHashLength is the length of the client data hash the helpers
// expect, in bytes -- a SHA-256 digest.
const fido2ClientDataHashLength = 32

// Line numbers in the helper protocols, from the fido2-cred(1) and
// fido2-assert(1) output formats.
//
// They are named rather than written at the call sites because they are the
// single most fragile assumption in this file: a helper that grows a field
// silently moves the credential to a different line, and the failure mode is a
// keyslot that enrolls cleanly and opens nothing.
const (
	// fido2CredIDLine is the credential id in `fido2-cred -M` output.
	fido2CredIDLine = 5

	// fido2AssertSecretLine is the hmac-secret in `fido2-assert -G -h` output
	// for the assertion THIS PACKAGE PERFORMS.
	//
	// fido2-assert(1) OUTPUT FORMAT lists, for each assertion:
	//
	//	1. client data hash      4. assertion signature
	//	2. relying party id      5. user id, IF CREDENTIAL RESIDENT
	//	3. authenticator data    6. hmac secret, if -h
	//	                         7. largeBlobKey, if -b
	//
	// Field 5 is CONDITIONAL, so the secret is on line 6 only when the
	// assertion was obtained from a resident (discoverable) credential. This
	// package always supplies a credential id -- FIDO2Params.validate refuses a
	// binding without one, and `-r` is never passed to fido2-assert -- so the
	// user id is not emitted and the secret is on line 5. `-b` is never passed
	// either, so nothing follows it.
	//
	// NOT EXECUTED AGAINST HARDWARE. The ordering is the documented one and it
	// could not be confirmed on this host: a production authenticator is
	// attached and enrolling against it is forbidden. CTAP2 leaves the
	// authenticator some latitude about returning user information for a
	// single-entry allow list, which is precisely the latitude that would shift
	// this line -- so the secret's LENGTH is checked as well as its position.
	// See fido2Provider.Passphrase: field 4, the signature, is a ~70-byte DER
	// blob and would be refused rather than enrolled.
	fido2AssertSecretLine = 5
)

// FIDO2SecretLength is the length of the hmac-secret an authenticator derives
// from a single salt, in bytes.
//
// It is checked rather than assumed, and that check is the backstop for
// fido2AssertSecretLine: reading the wrong line yields a field of some other
// length, and refusing it turns a credential that enrolls cleanly and never
// opens the volume into an error at enrollment time.
const FIDO2SecretLength = 32

// fido2SecretEncoding is THE ONE PLACE the enrolled form of a FIDO2
// hmac-secret is decided, and every path -- enrollment and unlock, this
// library's own and a token someone else wrote -- goes through it.
//
// # What is enrolled is not the secret
//
// systemd does not enroll the raw 32 bytes the authenticator produces. It
// enrolls the BASE64 TEXT of those bytes as an ASCII passphrase. Enrolling the
// raw bytes instead produces a keyslot that systemd-cryptsetup can never open,
// and vice versa.
//
// That it base64-encodes before enrolling is VERIFIED, on systemd 255: the
// string "Failed to base64 encode secret key: %m" is in the systemd-cryptenroll
// binary, alongside the token type "systemd-fido2" and the field names this
// package writes.
//
// # Which base64, MEASURED against a real artifact
//
// Standard alphabet, padded. That was an inference until three YubiKeys were
// enrolled into a real volume with systemd-cryptenroll (systemd 255, cryptsetup
// 2.7.0) and the resulting header was counted. Across the six base64 members of
// the three tokens it wrote -- fido2-credential and fido2-salt:
//
//	standard-only characters (+ /)   4
//	URL-safe-only characters (- _)   0
//	padding characters       (=)     9
//
// The nine padding characters settle padding OUTRIGHT: base64.RawStdEncoding
// and base64.RawURLEncoding emit none, ever, so neither is what wrote that
// header. The alphabet count settles the alphabet for those fields: over
// roughly 250 characters of random material a URL-safe encoder would be
// expected to emit several "-" or "_", and it emitted none while emitting four
// "+" or "/".
//
// This matters because the choice was NOT decidable from the binary. systemd's
// shared library carries both tables adjacent to each other -- one ending
// "0123456789-_", the other "0123456789+/" -- so reading the string table
// showed only that both exist. An artifact was the only thing that could
// distinguish them, and a header somebody's volume actually depends on is a
// better one than anything that could have been synthesized here.
//
// # What this still does not prove
//
// It proves the encoding of the TOKEN FIELDS. The secret-as-passphrase goes
// through the same systemd base64 helper, which makes this strong evidence for
// that path rather than direct proof of it. Settling it outright takes one
// non-destructive step -- run fido2-assert with the recorded credential and
// salt, base64 the result, offer it to `cryptsetup luksOpen --test-passphrase`
// -- and an assertion only reads the key.
//
// Until that lands, this variable and the function below remain the whole of
// the exposure: if the passphrase path ever turns out to differ, one of the
// other three encodings goes here and nothing else in the package moves. That
// is exactly why the helper's own output is never passed through untouched, but
// decoded and RE-ENCODED through this encoder on every path.
var fido2SecretEncoding = base64.StdEncoding

// normalizeFIDO2Secret turns a helper's base64 output line into the credential
// that is actually enrolled.
//
// It decodes and re-encodes rather than forwarding the helper's bytes, so the
// enrolled form is decided HERE and not by whatever the helper happened to
// print. A line that does not decode is refused: a credential built from
// garbage enrolls perfectly well and opens nothing, which is the failure this
// package exists to make impossible.
func normalizeFIDO2Secret(line []byte) (*enclave.MemoryEnclave, error) {
	const op = "fido2 secret"

	// Refused HERE rather than left to the allocator. An empty input is a
	// protocol failure -- the authenticator returned no secret -- and reporting
	// it as "protected memory unavailable" would send an operator to look at
	// RLIMIT_MEMLOCK for a problem with their key.
	if len(line) == 0 {
		return nil, &KeyProviderError{
			Op:  op,
			Err: &errs.Error{Kind: ErrHelperOutput, Detail: "the authenticator returned an empty secret"},
		}
	}

	raw, err := custody.New(op, fido2SecretEncoding.DecodedLen(len(line)))
	if err != nil {
		return nil, err
	}
	defer custody.Release(raw)

	var rawLen int
	if err := secret.Borrow(op, raw, func(dst []byte) error {
		n, err := fido2SecretEncoding.Decode(dst, line)
		if err != nil {
			return &KeyProviderError{
				Op: op,
				Err: &errs.Error{
					Kind:   ErrHelperOutput,
					Detail: fmt.Sprintf("the authenticator's secret is not %s base64", fido2EncodingName()),
				},
			}
		}
		rawLen = n
		return nil
	}); err != nil {
		return nil, err
	}
	if rawLen == 0 {
		return nil, &KeyProviderError{
			Op:  op,
			Err: &errs.Error{Kind: ErrHelperOutput, Detail: "the authenticator returned an empty secret"},
		}
	}

	encoded, err := custody.New(op, fido2SecretEncoding.EncodedLen(rawLen))
	if err != nil {
		return nil, err
	}
	if err := secret.Borrow(op, raw, func(src []byte) error {
		return secret.Borrow(op, encoded, func(dst []byte) error {
			fido2SecretEncoding.Encode(dst, src[:rawLen])
			return nil
		})
	}); err != nil {
		custody.Release(encoded)
		return nil, err
	}

	return encoded, nil
}

// fido2EncodingName describes the encoding in an error message, so a report from
// the field says which alphabet was expected without the reader having to go
// and look.
func fido2EncodingName() string {
	switch fido2SecretEncoding {
	case base64.StdEncoding:
		return "standard, padded"
	case base64.RawStdEncoding:
		return "standard, unpadded"
	case base64.URLEncoding:
		return "URL-safe, padded"
	case base64.RawURLEncoding:
		return "URL-safe, unpadded"
	default:
		return "the configured"
	}
}

// FIDO2Params is what a volume's FIDO2 binding consists of: which credential on
// which authenticator, salted with what, and what the user has to do to use it.
//
// None of it is secret. All of it is written into the LUKS2 header in the
// clear -- the security comes from the authenticator refusing to derive the
// secret without the credential and the user's consent, not from hiding the
// parameters.
type FIDO2Params struct {
	// RelyingParty is the rp id the credential was made under. Empty means
	// DefaultFIDO2RelyingParty.
	RelyingParty string

	// CredentialID identifies the credential on the authenticator.
	CredentialID []byte

	// Salt is the hmac-secret salt. The same salt against the same credential
	// yields the same secret; a different salt yields a different one.
	Salt []byte

	// UserPresence requires a touch (`-t up=true`).
	UserPresence bool

	// UserVerification requires the authenticator to verify the user, by
	// biometric or on-device PIN (`-t uv=true`).
	UserVerification bool

	// ClientPin requires a PIN typed to the helper (`-t pin=true`). The helper
	// prompts for it on its own controlling terminal, which is why an
	// unattended unlock must not set this.
	ClientPin bool
}

func (p FIDO2Params) relyingParty() string {
	if p.RelyingParty != "" {
		return p.RelyingParty
	}
	return DefaultFIDO2RelyingParty
}

// validate refuses a binding that cannot produce a secret.
func (p FIDO2Params) validate() error {
	switch {
	case len(p.CredentialID) == 0:
		return &KeyProviderError{Op: "fido2 binding", Err: &errs.Error{Kind: ErrInvalidFIDO2Binding, Detail: "no credential id"}}
	case len(p.Salt) == 0:
		return &KeyProviderError{Op: "fido2 binding", Err: &errs.Error{Kind: ErrInvalidFIDO2Binding, Detail: "no salt"}}
	}
	return nil
}

// NewFIDO2Salt draws a fresh hmac-secret salt.
//
// It is ordinary memory on purpose: the salt is written into the header in the
// clear and protecting the copy in this process would protect nothing.
func NewFIDO2Salt() ([]byte, error) {
	salt, err := randomBytes(FIDO2SaltLength)
	if err != nil {
		return nil, &KeyProviderError{Op: "fido2 salt", Err: err}
	}
	return salt, nil
}

// fido2Provider is the unlock side of a FIDO2 binding: a CommandKeyProvider
// running fido2-assert, plus the normalization that decides what the enrolled
// credential actually is.
//
// It WRAPS rather than reimplements. There is one exec path in this package and
// this is not a second one -- what is added here is the base64 round trip and
// nothing else.
type fido2Provider struct {
	cmd *CommandKeyProvider
}

var _ KeyProvider = (*fido2Provider)(nil)

func (p *fido2Provider) Token() *Token { return p.cmd.Token() }

func (p *fido2Provider) Passphrase(ctx context.Context) (*enclave.MemoryEnclave, error) {
	line, err := p.cmd.Passphrase(ctx)
	if err != nil {
		return nil, err
	}
	defer custody.Release(line)

	var credential *enclave.MemoryEnclave
	if err := secret.Borrow("fido2 secret", line, func(b []byte) error {
		var err error
		credential, err = normalizeFIDO2Secret(b)
		return err
	}); err != nil {
		return nil, err
	}

	// The enrolled credential is base64 TEXT, so its length is the encoded
	// length of a FIDO2SecretLength secret. Anything else means the line taken
	// from the helper was not the hmac-secret -- see fido2AssertSecretLine --
	// and enrolling it would produce a keyslot that opens nothing.
	if want := fido2SecretEncoding.EncodedLen(FIDO2SecretLength); credential.Size() != want {
		custody.Release(credential)
		return nil, &KeyProviderError{
			Op: "fido2 secret",
			Err: &errs.Error{
				Kind: ErrHelperOutput,
				Detail: fmt.Sprintf("line %d of the assertion is not a %d-byte hmac-secret; the helper's output format is not the one this package expects",
					p.cmd.Line, FIDO2SecretLength),
			},
		}
	}

	return credential, nil
}

// NewFIDO2KeyProvider builds the provider that unlocks a volume with a FIDO2
// authenticator, and the token that records the binding.
func NewFIDO2KeyProvider(params FIDO2Params, cfg ExecConfig) (KeyProvider, error) {
	if err := params.validate(); err != nil {
		return nil, err
	}
	device, err := cfg.device()
	if err != nil {
		return nil, err
	}

	clientData, err := newFIDO2ClientDataHash()
	if err != nil {
		return nil, err
	}

	// The assertion's input fields, one per line, in the order fido2-assert
	// reads them: client data hash, rp id, credential id, salt.
	stdin := fido2Lines(
		base64.StdEncoding.EncodeToString(clientData),
		params.relyingParty(),
		base64.StdEncoding.EncodeToString(params.CredentialID),
		base64.StdEncoding.EncodeToString(params.Salt),
	)

	args := []string{"-G", "-h"}
	if params.UserPresence {
		args = append(args, "-t", "up=true")
	}
	if params.ClientPin {
		args = append(args, "-t", "pin=true")
	}
	if params.UserVerification {
		args = append(args, "-v")
	}
	// "--" ends the options: a device name is never read as one.
	args = append(args, "--", device)

	return &fido2Provider{
		cmd: &CommandKeyProvider{
			Path:  cfg.assertPath(),
			Args:  args,
			Stdin: stdin,
			Line:  fido2AssertSecretLine,
			Meta:  fido2Token(params),
		},
	}, nil
}

// FIDO2CredentialOptions are the enrollment-time choices that are made once,
// when the credential is created on the authenticator, and cannot be changed
// afterwards.
type FIDO2CredentialOptions struct {
	// RelyingParty is the rp id to create the credential under. Empty means
	// DefaultFIDO2RelyingParty.
	RelyingParty string

	// UserName and UserID identify the credential to the authenticator. They
	// are only meaningful for a resident credential.
	UserName string
	UserID   []byte

	// Resident asks for a discoverable (resident) credential, which the
	// authenticator stores itself so that unlocking needs no credential id from
	// the header (`-r`).
	Resident bool

	// UserVerification requires the authenticator to verify the user at
	// creation (`-v`).
	UserVerification bool
}

// NewFIDO2Credential creates a credential on an authenticator and returns its
// id.
//
// The `-h` flag is not optional and is not a preference: it is what enables the
// hmac-secret extension ON THE CREDENTIAL, at creation. A credential made
// without it can never produce a secret, no matter what the assertion asks for,
// and the failure surfaces much later as an unlock that yields nothing.
//
// The credential id is NOT secret -- it is written into the LUKS2 header in the
// clear -- but it arrives through the same locked-memory path as everything
// else the helpers produce, because that path is the provider, and having a
// second one would mean having a second thing to get right.
func NewFIDO2Credential(ctx context.Context, cfg ExecConfig, opts FIDO2CredentialOptions) ([]byte, error) {
	device, err := cfg.device()
	if err != nil {
		return nil, err
	}

	clientData, err := newFIDO2ClientDataHash()
	if err != nil {
		return nil, err
	}

	userID := opts.UserID
	if len(userID) == 0 {
		userID, err = randomBytes(fido2ClientDataHashLength)
		if err != nil {
			return nil, &KeyProviderError{Op: "fido2 user id", Err: err}
		}
	}
	rp := opts.RelyingParty
	if rp == "" {
		rp = DefaultFIDO2RelyingParty
	}
	userName := opts.UserName
	if userName == "" {
		userName = "luks2"
	}

	// The creation input fields, one per line, in the order fido2-cred reads
	// them: client data hash, rp id, user name, user id.
	stdin := fido2Lines(
		base64.StdEncoding.EncodeToString(clientData),
		rp,
		userName,
		base64.StdEncoding.EncodeToString(userID),
	)

	args := []string{"-M", "-h"}
	if opts.Resident {
		args = append(args, "-r")
	}
	if opts.UserVerification {
		args = append(args, "-v")
	}
	args = append(args, "--", device, "es256")

	cred := &CommandKeyProvider{
		Path:  cfg.credPath(),
		Args:  args,
		Stdin: stdin,
		Line:  fido2CredIDLine,
	}

	encoded, err := cred.Passphrase(ctx)
	if err != nil {
		return nil, err
	}
	defer custody.Release(encoded)

	var id []byte
	if err := secret.Borrow("fido2 credential id", encoded, func(b []byte) error {
		decoded, err := base64.StdEncoding.DecodeString(string(b))
		if err != nil {
			return &KeyProviderError{
				Op:  "fido2 credential id",
				Err: &errs.Error{Kind: ErrHelperOutput, Detail: "the credential id is not base64"},
			}
		}
		id = decoded
		return nil
	}); err != nil {
		return nil, err
	}

	return id, nil
}

// fido2Lines renders the helpers' stdin: one field per line, newline-terminated.
func fido2Lines(fields ...string) []byte {
	var buf bytes.Buffer
	for _, f := range fields {
		buf.WriteString(f)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// newFIDO2ClientDataHash draws the client data hash the helpers require.
//
// It is random rather than fixed, and it does NOT participate in the
// hmac-secret derivation: the secret is a function of the credential, the
// authenticator's own seed and the salt. Nothing depends on this value being
// the same at enrollment and at unlock, which is why it is not recorded.
func newFIDO2ClientDataHash() ([]byte, error) {
	h, err := randomBytes(fido2ClientDataHashLength)
	if err != nil {
		return nil, &KeyProviderError{Op: "fido2 client data hash", Err: err}
	}
	return h, nil
}

// ---------------------------------------------------------------------------
// Token <-> FIDO2Params
//
// EVERY read and write of a Token's FIDO2 fields in this package happens in the
// two functions below. That is not tidiness: the token schema is under
// concurrent change (the three requirement flags are becoming *bool so that
// "absent" and "false" stop being the same value), and confining the schema to
// one pair of functions means the reconciliation is a diff nobody has to search
// for.
// ---------------------------------------------------------------------------

// fido2Token renders a binding as the token that goes in the header.
//
// FIDO2UPRequired is written EXPLICITLY, including when it is false. The member
// is a *bool precisely because false is a value systemd records on purpose --
// `--fido2-with-user-presence=no` writes it -- and this package knows which of
// the two it means, because it is the one assembling the binding. Emitting the
// pointer rather than relying on omitempty is what keeps "presence not required"
// distinguishable from "this token says nothing about presence" on the way back
// in. See Token (types.go) and #153.
//
// The PIN and user-verification requirements are written the same way, for the
// same reason, and because a token that omitted them was rebuilt by
// fido2ParamsFromToken into a binding that asked for neither: an unlock driven
// from the header dropped the PIN the enrollment demanded (#246 D9).
func fido2Token(params FIDO2Params) *Token {
	userPresence := params.UserPresence
	clientPin := params.ClientPin
	userVerification := params.UserVerification
	return &Token{
		Type:                   fido2TokenType,
		FIDO2Credential:        base64.StdEncoding.EncodeToString(params.CredentialID),
		FIDO2Salt:              base64.StdEncoding.EncodeToString(params.Salt),
		FIDO2RP:                params.relyingParty(),
		FIDO2ClientPinRequired: &clientPin,
		FIDO2UPRequired:        &userPresence,
		FIDO2UVRequired:        &userVerification,
	}
}

// fido2ParamsFromToken reads a binding back out of a token.
//
// A field that does not decode is REFUSED rather than defaulted. A binding
// assembled from a half-read token produces an assertion that returns a
// different secret, and "the volume no longer opens" is not the error message
// anyone should get for a malformed base64 field.
func fido2ParamsFromToken(t *Token) (FIDO2Params, error) {
	credential, err := base64.StdEncoding.DecodeString(t.FIDO2Credential)
	if err != nil {
		return FIDO2Params{}, &KeyProviderError{
			Op:  "fido2 token",
			Err: &errs.Error{Kind: ErrInvalidFIDO2Binding, Detail: "fido2-credential is not base64"},
		}
	}
	salt, err := base64.StdEncoding.DecodeString(t.FIDO2Salt)
	if err != nil {
		return FIDO2Params{}, &KeyProviderError{
			Op:  "fido2 token",
			Err: &errs.Error{Kind: ErrInvalidFIDO2Binding, Detail: "fido2-salt is not base64"},
		}
	}

	// An ABSENT fido2-up-required reads as false, which is what this package
	// has always decoded it to: the member was a plain bool until #153, so
	// "not set" and false were the same value on the way in and every token
	// read so far was read this way. Making the member a pointer changed what
	// can be WRITTEN, not how a token that omits it is understood, and
	// inventing a different default here would silently change whether an
	// existing binding demands a touch.
	//
	// The PIN and user-verification requirements are read the same way: absent
	// is false, present is what it says.
	params := FIDO2Params{
		RelyingParty:     t.FIDO2RP,
		CredentialID:     credential,
		Salt:             salt,
		UserPresence:     t.FIDO2UPRequired != nil && *t.FIDO2UPRequired,
		ClientPin:        t.FIDO2ClientPinRequired != nil && *t.FIDO2ClientPinRequired,
		UserVerification: t.FIDO2UVRequired != nil && *t.FIDO2UVRequired,
	}
	if err := params.validate(); err != nil {
		return FIDO2Params{}, err
	}
	return params, nil
}

// fido2ProviderFromToken is ProviderFromToken's FIDO2 arm.
func fido2ProviderFromToken(t *Token, cfg ExecConfig) (KeyProvider, error) {
	params, err := fido2ParamsFromToken(t)
	if err != nil {
		return nil, err
	}
	return NewFIDO2KeyProvider(params, cfg)
}

// ---------------------------------------------------------------------------
// Errors
//
// The external-key sentinels are in errors.go with every other sentinel. The
// types here follow the same shape: a structured type carrying what a
// diagnosis needs, and an Is that reports the type as its sentinel so a caller
// never has to know the type exists.
// ---------------------------------------------------------------------------

// KeyProviderError reports a failure in obtaining or enrolling an external
// credential, naming the step it happened in.
type KeyProviderError struct {
	// Op names the step, for example "enroll" or "fido2 secret". It never
	// carries credential material.
	Op  string
	Err error
}

func (e *KeyProviderError) Error() string {
	return fmt.Sprintf("%s: %s: %v", ErrKeyProvider.Error(), e.Op, e.Err)
}

func (e *KeyProviderError) Unwrap() error { return e.Err }

// Is reports every KeyProviderError as ErrKeyProvider, so a caller can match
// the sentinel without knowing this type, while errors.Is also still reaches
// the specific cause through Unwrap.
func (e *KeyProviderError) Is(target error) bool {
	return target == ErrKeyProvider
}

// HelperError reports that a helper binary could not be run, or ran and
// refused.
//
// Stderr is included because it is where these helpers say what actually
// happened -- "no device found", "PIN required", "operation denied" -- and an
// operator holding a key that will not open a volume needs that sentence rather
// than an exit code. It carries no credential material: the credential is on
// stdout, which is never put in an error.
type HelperError struct {
	// Path is the binary that was run.
	Path string

	// ExitCode is the helper's exit status, or -1 when it never ran.
	ExitCode int

	// Stderr is what the helper said, bounded at maxHelperStderr.
	Stderr string

	Err error
}

func (e *HelperError) Error() string {
	msg := fmt.Sprintf("%s: %s exited %d", ErrKeyProvider.Error(), e.Path, e.ExitCode)
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	return msg
}

func (e *HelperError) Unwrap() error { return e.Err }

// Is reports a HelperError as ErrKeyProvider as well as through its cause, so
// both the general and the specific match work.
func (e *HelperError) Is(target error) bool {
	return target == ErrKeyProvider
}

// OrphanedKeyslotError reports a keyslot holding a live credential that no
// token describes and that could not be removed.
//
// It names the slot because that number is the only way back: an operator
// removes it with `luks2 killslot <device> <n>`, and no other record of it
// exists anywhere.
type OrphanedKeyslotError struct {
	// Keyslot is the slot holding the credential.
	Keyslot int

	// Err is why the token could not be written -- the original failure.
	Err error

	// Cause is why the keyslot could not then be removed.
	Cause error
}

func (e *OrphanedKeyslotError) Error() string {
	return fmt.Sprintf("%s: keyslot %d holds a credential no token describes: the token write failed (%v) and the keyslot could not be removed (%v). Remove it with: luks2 killslot <device> %d",
		ErrOrphanedKeyslot.Error(), e.Keyslot, e.Err, e.Cause, e.Keyslot)
}

func (e *OrphanedKeyslotError) Unwrap() error { return e.Err }

// Is reports an OrphanedKeyslotError as both ErrOrphanedKeyslot and
// ErrKeyProvider: it is the provider vocabulary, and it is also the one
// condition a caller may want to single out.
func (e *OrphanedKeyslotError) Is(target error) bool {
	return target == ErrOrphanedKeyslot || target == ErrKeyProvider
}
