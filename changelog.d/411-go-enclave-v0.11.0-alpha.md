### Changed

- **go-luks2 requires go-enclave v0.11.1-alpha (#411).** The release adds the
  linux-secretmem backend (`enclave.NewSecretMemory`), `Sealed.OpenIn` and an
  arm-trustzone harness behind the `optee` tag, and changes no API go-luks2
  calls. Nothing changes for go-luks2 callers.
