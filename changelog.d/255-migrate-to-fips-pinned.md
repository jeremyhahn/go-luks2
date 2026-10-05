### Security

- **`MigrateToFIPS` stays on the device it locked (#255).** It opened the
  device path again for every read, write, wipe and medium check, so a path
  re-pointed mid-import could send the new keyslot, the header rewrites and the
  wipes of the old keyslots to a device that was never locked or read. It now
  opens the path once, locks that descriptor, and does everything through it;
  the reads past the page cache reopen the same inode through `/proc/self/fd`.
