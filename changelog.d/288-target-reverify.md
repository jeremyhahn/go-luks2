### Security

- **Activation re-verifies the key against the header it maps (#288).**
  `(*Volume).Target`, and so `dmcrypt.Activate`, used to re-read the header
  but check only the key's size, so a header rewritten between `Unlock` and
  activation, or a key from another volume, was mapped anyway. The key is now
  verified against the re-read header's digest for the mapped segment, and a
  key it does not verify is refused with `ErrWrongKey`.
