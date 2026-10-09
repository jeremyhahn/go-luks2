package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

// keyslotWriteRunners are the keyslot-writing commands with the arguments that
// take them as far as the device, so each failure below lands on the step it
// names and no earlier one.
func keyslotWriteRunners() []struct {
	name string
	run  func(context.Context, *env, []string) error
	// args builds the argument list for a device path and a slot argument.
	args func(device, slot string) []string
} {
	return []struct {
		name string
		run  func(context.Context, *env, []string) error
		args func(device, slot string) []string
	}{
		{"addkey", runAddKey, func(d, _ string) []string { return append(append([]string{}, fastKDFArgs...), d) }},
		{"changekey", runChangeKey, func(d, s string) []string { return append(append([]string{}, fastKDFArgs...), d, s) }},
		{"removekey", runRemoveKey, func(d, s string) []string { return []string{d, s} }},
		{"killslot", runKillSlot, func(d, s string) []string { return []string{d, s} }},
	}
}

// TestKeyslotWriteCommandsRefuseAMissingDevice drives every command past its
// credential prompts to luks2.Open on a path that does not exist.
func TestKeyslotWriteCommandsRefuseAMissingDevice(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.img")
	for _, c := range keyslotWriteRunners() {
		t.Run(c.name, func(t *testing.T) {
			e, _, _, _, _ := newTestEnv(bytes.NewBufferString("first-pass\nsecond-pass\n"))
			if err := c.run(context.Background(), e, c.args(missing, "0")); err == nil {
				t.Fatalf("%s: want an error for a device that does not exist", c.name)
			}
		})
	}
}

// TestKeyslotWriteCommandsRefuseEmptyInput gives every command a stdin with
// no credential in it, so the first prompt cannot be answered.
func TestKeyslotWriteCommandsRefuseEmptyInput(t *testing.T) {
	path := newTestVolumeImage(t, "keyslot-empty-input.img")
	for _, c := range keyslotWriteRunners() {
		t.Run(c.name, func(t *testing.T) {
			e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
			if err := c.run(context.Background(), e, c.args(path, "0")); err == nil {
				t.Fatalf("%s: want an error when no passphrase can be read", c.name)
			}
		})
	}
}

// TestKeyslotWriteCommandsRefuseASecondMissingPassphrase answers the first
// prompt only, so the commands that ask twice fail on the second.
func TestKeyslotWriteCommandsRefuseASecondMissingPassphrase(t *testing.T) {
	path := newTestVolumeImage(t, "keyslot-one-input.img")
	for _, c := range keyslotWriteRunners() {
		if c.name != "addkey" && c.name != "changekey" {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			e, _, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\n"))
			if err := c.run(context.Background(), e, c.args(path, "0")); err == nil {
				t.Fatalf("%s: want an error when the new passphrase cannot be read", c.name)
			}
		})
	}
}

// TestKeyslotCommandsRefuseANonNumericSlot covers the slot argument.
func TestKeyslotCommandsRefuseANonNumericSlot(t *testing.T) {
	path := newTestVolumeImage(t, "keyslot-bad-slot.img")
	for _, c := range keyslotWriteRunners() {
		if c.name == "addkey" {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			e, _, _, _, _ := newTestEnv(bytes.NewBufferString(testPassphrase + "\nsecond-pass\n"))
			if err := c.run(context.Background(), e, c.args(path, "not-a-slot")); err == nil {
				t.Fatalf("%s: want an error for a slot that is not a number", c.name)
			}
		})
	}
}

// TestRunChangeKeyRefusesPBKDF2SHA1 is the changekey counterpart of the addkey
// test: a refused KDF choice is reported before any credential is asked for.
func TestRunChangeKeyRefusesPBKDF2SHA1(t *testing.T) {
	e, _, _, _, _ := newTestEnv(&bytes.Buffer{})
	if err := runChangeKey(context.Background(), e, []string{"--pbkdf", "pbkdf2", "--hash", "sha1", "/dev/sdb1", "0"}); err == nil {
		t.Fatal("runChangeKey: want an error for pbkdf2 with sha1")
	}
}
