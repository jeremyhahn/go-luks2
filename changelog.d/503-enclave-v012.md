### Changed

- **go-luks2 requires go-enclave v0.12.0-alpha (#503).** It is go-enclave's
  first public release: its root module now depends only on `golang.org/x/sys`
  (v0.50.0, the version go-luks2 already requires) and needs Go 1.27.4, the
  minimum go-luks2 already sets. The residue sweep behind its conformance
  checks skips a thread-stack guard page on kernels that report one instead of
  failing. Its one breaking change removes the `backends/imxele` module, which
  go-luks2 never used, and it changes no API go-luks2 calls. Nothing changes
  for go-luks2 callers.
