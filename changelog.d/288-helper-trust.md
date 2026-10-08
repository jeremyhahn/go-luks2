### Security

- **A key helper must be a file only root or the caller could have written
  (#288).** `keyprovider.Command` (and the FIDO2 helpers it runs) now applies
  the trusted-executable checks every system tool gets before it runs the
  helper: a regular executable file owned by root or the calling user, not
  group- or world-writable, reached only through directories that are the same
  or sticky and through symlinks owned by root or the caller. A helper that
  fails them is refused with `ErrHelperFailed` and is not run. Install helpers
  where only root can replace them.
- **A helper or system tool runs from the file that was checked (#288).** The
  path is walked from `/` one descriptor at a time, so every directory and
  symlink it passes through is judged, including those a symlink later leads
  away from, and the program is executed from the checked descriptor rather
  than reopened by path. Running a key helper now needs Linux with `/proc`
  mounted; elsewhere it is refused.
