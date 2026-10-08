### Fixed

- **`(*loop.Device).Detach` no longer detaches a loop device that was
  reassigned in between (#288).** It checks, on the descriptor it clears,
  that the device is still backed by the file recorded when the `Device` was
  obtained, and refuses with the new `loop.ErrDeviceReassigned` otherwise, or
  with an I/O error when nothing is attached any more. A `Device` from
  `Lookup` is held to the file attached when it was looked up.
