### Fixed

- **A nil Volume or Key is refused with `ErrInvalidArgument` instead of
  panicking (#211).** `dmcrypt.Activate` checks both before it consults the
  device-mapper or the kernel keyring, so the refusal is the same as root and
  as an unprivileged user; before, root reached the nil Volume and the process
  died. `Volume.AddKeyslot`, `Volume.ChangeKeyslot` and `Volume.Enroll` refuse
  a nil Key, and a zero `Key{}` that holds no key, the same way. A caller
  that passes a value it got from `Open` and `Unlock` sees no change.
