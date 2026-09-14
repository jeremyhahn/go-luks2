### Fixed

- **The CLI no longer acts on a mount check that could not run (#185).**
  `IsMounted` fails only when `/proc/mounts` cannot be read — an absent mapper
  node is simply not listed and returns `false, nil` — so an error from it means
  the mount state is UNKNOWN, never "not mounted".

  Three commands treated the unknown as the permissive answer. `luks2 close`
  read `if err == nil && mounted`, which skipped the check entirely when it
  could not run and went on to **lock a volume whose filesystem may still be
  mounted**, tearing it out from under its writers. `luks2 mount` discarded the
  error and would **mount over a mountpoint that may be in use**, hiding
  whatever was there. `luks2 unmount` discarded it too and reported a false
  "Not mounted", which is safe but sends an operator looking in the wrong place.

  Each now distinguishes mounted, not mounted, and could-not-determine, and
  refuses on the third with the underlying cause.
