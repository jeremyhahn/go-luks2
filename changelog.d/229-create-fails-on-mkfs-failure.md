### Fixed

- **`luks2 create` fails when the filesystem cannot be created (#229).**
  When `MakeFilesystem` failed for a supported type, for example because
  `mkfs.ext4` is missing, `create` printed a warning followed by "Volume is
  ready" and exited 0. That left an unlocked mapping with no filesystem on
  it, and a script that checked the exit status took it as a usable volume.
  `create` now exits 1 and prints the cause. It closes the `luks-auto`
  mapping it opened and then detaches the loop device it attached, and it
  says that the LUKS2 container file is valid and was kept. If the mapping
  cannot be closed, it says the volume is still unlocked and prints the
  `luks2 close` and `losetup -d` commands to finish the cleanup.
