// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package recoverykey renders recovery keys as text and reads them back,
// entirely inside protected memory.
//
// A recovery key's printed text IS the credential a keyslot holds, so every
// step here works on bytes in locked pages and never builds a Go string: a
// string holding a credential can never be wiped, and strings.ToUpper,
// ToLower, TrimSpace and Split would each make another one.
package recoverykey

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// Format is how a recovery key's random bytes are written down.
type Format uint8

const (
	// Dashed is upper-case hex in dash-separated groups of six, as BitLocker
	// writes its keys.
	Dashed Format = iota
	// Hex is lower-case hex.
	Hex
	// Base64 is standard, padded base64.
	Base64
)

// dashedGroupSize is the number of hex characters between dashes.
const dashedGroupSize = 6

// Len returns the exact number of bytes n random bytes occupy in f, so the
// rendering can be allocated in locked memory up front rather than grown on
// the heap.
func Len(n int, f Format) int {
	switch f {
	case Base64:
		return base64.StdEncoding.EncodedLen(n)
	case Hex:
		return hex.EncodedLen(n)
	default:
		hexLen := hex.EncodedLen(n)
		if hexLen == 0 {
			return 0
		}
		groups := (hexLen + dashedGroupSize - 1) / dashedGroupSize
		return hexLen + groups - 1
	}
}

// Render writes the random bytes held in key out in f, into a new enclave c
// allocates. The rendering is the credential, and it never exists outside
// locked memory.
func Render(c secret.Custody, key enclave.ByteAccess, f Format) (enclave.ByteAccess, error) {
	credential, err := c.New("recovery key", Len(key.Size(), f))
	if err != nil {
		return nil, err
	}
	if err := secret.Borrow("recovery key", key, func(raw []byte) error {
		return secret.Borrow("recovery key", credential, func(dst []byte) error {
			renderInto(dst, raw, f)
			return nil
		})
	}); err != nil {
		c.Release(credential)
		return nil, err
	}
	return credential, nil
}

// Hash returns the SHA-256 of the credential text, hex-encoded. It is a
// one-way function of the credential and is not itself secret: it is printed
// beside the key so a transcription can be checked without the volume. It is
// computed inside the borrow only because that is where the text is readable.
func Hash(credential enclave.ByteAccess) (string, error) {
	var sum [sha256.Size]byte
	if err := secret.Borrow("recovery key", credential, func(b []byte) error {
		sum = sha256.Sum256(b)
		return nil
	}); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum[:]), nil
}

// renderInto renders key into dst, which must be exactly Len(len(key), f)
// bytes.
//
// The dashed form is built by encoding the hex RIGHT-ALIGNED in dst and then
// walking left to right inserting separators: the read cursor stays ahead of
// the write cursor for every group, so the expansion needs no second buffer.
func renderInto(dst, key []byte, f Format) {
	switch f {
	case Base64:
		base64.StdEncoding.Encode(dst, key)
	case Hex:
		hex.Encode(dst, key)
	default:
		hexLen := hex.EncodedLen(len(key))
		if hexLen == 0 {
			return
		}

		hex.Encode(dst[len(dst)-hexLen:], key)

		w, r := 0, len(dst)-hexLen
		for remaining := hexLen; remaining > 0; {
			n := min(dashedGroupSize, remaining)
			copy(dst[w:w+n], dst[r:r+n])
			w += n
			r += n
			remaining -= n
			if remaining > 0 {
				dst[w] = '-'
				w++
			}
		}

		upperASCII(dst)
	}
}

// Credential returns the credential typed or pasted text names, in a new
// enclave c allocates: the text with surrounding whitespace trimmed, because a
// paste carries it and no keyslot holds it.
//
// NOTHING ELSE IS TOUCHED. Case is significant, the dashes are significant, and
// a credential that has been "canonicalized" on the way in is a credential the
// volume has never seen. That is the contract cryptsetup offers when the same
// string is pasted at its own prompt, and the two must agree: the credential is
// text precisely so that stock cryptsetup can open the volume.
//
// A newline inside the trimmed text means more than one line was handed in --
// a whole file, most likely -- and is refused rather than silently taking the
// first line, because guessing which line somebody meant is how the wrong
// string gets enrolled or tested.
func Credential(c secret.Custody, text enclave.ByteAccess) (enclave.ByteAccess, error) {
	var credential enclave.ByteAccess
	err := secret.Borrow("recovery key", text, func(b []byte) error {
		body := trimASCIISpace(b)
		if len(body) == 0 {
			return &errs.Error{Kind: errs.ErrInvalidCredential, Detail: "recovery key is empty"}
		}
		if bytes.IndexByte(body, '\n') >= 0 {
			return &errs.Error{Kind: errs.ErrInvalidCredential, Detail: "a recovery key is a single line; read a saved file line by line"}
		}
		var err error
		credential, err = c.Clone("recovery key", body)
		return err
	})
	if err != nil {
		return nil, err
	}
	return credential, nil
}

// FirstLine returns the first line of a recovery key file that is neither
// blank nor a comment, trimmed, as a SUB-SLICE of contents -- which the caller
// holds in locked memory -- or nil when there is none. It walks bytes rather
// than using strings.Split, which would allocate an unwipeable string per
// line of a file whose whole point is to hold a credential.
func FirstLine(contents []byte) []byte {
	for len(contents) > 0 {
		line := contents
		if i := bytes.IndexByte(contents, '\n'); i >= 0 {
			line, contents = contents[:i], contents[i+1:]
		} else {
			contents = nil
		}

		line = trimASCIISpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		return line
	}
	return nil
}

// Decode turns a rendering held in locked memory back into the KEY MATERIAL
// behind it, in a new enclave c allocates, normalising inside locked scratch.
//
// It is tolerant in a way Credential is deliberately not -- either case, with
// or without dashes, hex or base64 -- because it decodes a rendering rather
// than reproducing a credential. The format decision: dashes mean dashed hex;
// an all-hex even-length body is tried as hex first; a trailing '=' or any
// non-hex character admits base64; and hex is the fallback.
func Decode(c secret.Custody, rendered enclave.ByteAccess) (enclave.ByteAccess, error) {
	var key enclave.ByteAccess

	err := secret.Borrow("recovery key", rendered, func(raw []byte) error {
		body := trimASCIISpace(raw)
		if len(body) == 0 {
			return &errs.Error{Kind: errs.ErrInvalidCredential, Detail: "recovery key is empty"}
		}

		// Dashed: strip the separators and lower-case, into locked scratch.
		if bytes.IndexByte(body, '-') >= 0 {
			stripped, err := c.CloneFiltered("recovery key", body, func(b byte) bool { return b != '-' })
			if err != nil {
				return err
			}
			defer c.Release(stripped)

			return secret.Borrow("recovery key", stripped, func(hexBody []byte) error {
				lowerASCII(hexBody)
				key, err = decodeHex(c, hexBody)
				return err
			})
		}

		// Not dashed. The hex test is on the lower-cased body, so a WRITABLE
		// copy is taken to lower-case in: an enclave built from existing
		// material is frozen read-only, and a write through it faults.
		normalized, err := c.CloneWritable("recovery key", body)
		if err != nil {
			return err
		}
		defer c.Release(normalized)

		return secret.Borrow("recovery key", normalized, func(b []byte) error {
			lowerASCII(b)
			isHex := isAllHex(b)

			if isHex && len(b)%2 == 0 {
				if k, err := decodeHex(c, b); err == nil {
					key = k
					return nil
				}
			}

			// base64 is case-sensitive, so it decodes the ORIGINAL body rather
			// than the lower-cased copy.
			if body[len(body)-1] == '=' || !isHex {
				if k, err := decodeBase64(c, body); err == nil {
					key = k
					return nil
				}
			}

			key, err = decodeHex(c, b)
			return err
		})
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}

// decodeHex decodes hex bytes DIRECTLY into locked memory. The caller has
// already trimmed and lower-cased in place.
func decodeHex(c secret.Custody, src []byte) (enclave.ByteAccess, error) {
	n := hex.DecodedLen(len(src))
	invalid := &errs.Error{Kind: errs.ErrInvalidCredential, Detail: "recovery key is not valid hex"}
	if n == 0 {
		return nil, invalid
	}
	key, err := decodeExact(c, n, func(dst []byte) (int, error) {
		// hex.InvalidByteError names the offending byte, which is a
		// character of the credential: it is dropped, not wrapped.
		n, err := hex.Decode(dst, src)
		if err != nil {
			return n, invalid
		}
		return n, nil
	})
	return key, err
}

// decodeBase64 decodes base64 bytes DIRECTLY into locked memory.
func decodeBase64(c secret.Custody, src []byte) (enclave.ByteAccess, error) {
	n := base64.StdEncoding.DecodedLen(len(src))
	if n == 0 {
		return nil, base64.CorruptInputError(0)
	}
	return decodeExact(c, n, func(dst []byte) (int, error) {
		return base64.StdEncoding.Decode(dst, src)
	})
}

// decodeExact allocates maxLen bytes of locked scratch, lets decode fill it,
// and returns an enclave holding exactly the bytes decode reported.
//
// The two steps exist because base64's DecodedLen is an upper bound -- padding
// makes the real length shorter -- and an enclave sized from the bound would
// hand back trailing zeros as part of the key. The scratch is destroyed once
// the exact-sized enclave has been filled, so the surplus is wiped rather than
// merely ignored, and the caller's handle never aliases it.
func decodeExact(c secret.Custody, maxLen int, decode func(dst []byte) (int, error)) (enclave.ByteAccess, error) {
	scratch, err := c.New("recovery key", maxLen)
	if err != nil {
		return nil, err
	}
	defer c.Release(scratch)

	var exact enclave.ByteAccess
	err = secret.Borrow("recovery key", scratch, func(dst []byte) error {
		n, err := decode(dst)
		if err != nil {
			return err
		}
		if n == 0 {
			return &errs.Error{Kind: errs.ErrInvalidCredential, Detail: "recovery key is empty"}
		}
		exact, err = c.New("recovery key", n)
		if err != nil {
			return err
		}
		return secret.Borrow("recovery key", exact, func(out []byte) error {
			copy(out, dst[:n])
			return nil
		})
	})
	if err != nil {
		c.Release(exact)
		return nil, err
	}

	return exact, nil
}

// trimASCIISpace returns b without leading or trailing ASCII whitespace, as a
// sub-slice: strings.TrimSpace's byte equivalent, without the copy.
func trimASCIISpace(b []byte) []byte {
	start := 0
	for start < len(b) && isASCIISpace(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isASCIISpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isASCIISpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// lowerASCII lower-cases ASCII letters in place.
func lowerASCII(b []byte) {
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
}

// upperASCII upper-cases ASCII letters in place.
func upperASCII(b []byte) {
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
}

// isAllHex reports whether every byte is a lower-case hex digit.
func isAllHex(b []byte) bool {
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
