### Fixed

- **`luks2 recovery verify` help states the exit status it uses (#288).** The
  help said a key that does not open the volume exits 1; it exits 2, the
  wrong-passphrase status, as documented. The `does NOT open` line is now
  printed only when the key was tried and refused, not for a failure that
  never reached it.
