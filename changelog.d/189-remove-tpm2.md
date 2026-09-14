### Changed — BREAKING: `Token` no longer models TPM2 members

- **go-luks2 carries no TPM2 knowledge (#189).** go-xkms owns all hardware and
  cloud crypto — TPM2, PKCS#11, the KMS backends — and this is a Layer 0
  library. The nine `TPM2*` fields on `Token` and the `TokenTypeSystemdTPM2`
  constant are removed.

  **No data is lost.** The unknown-member passthrough carries a `systemd-tpm2`
  token through a read-modify-write byte for byte, so a token written by
  `systemd-cryptenroll` survives a header rewrite exactly as systemd wrote it —
  read it back with `GetToken` and every member is there. Only `type` and
  `keyslots`, which LUKS2 itself defines, remain typed.

  A consumer that needs to *interpret* such a token supplies it through
  `KeyProvider`: go-xkms returns the unsealed credential and the token that
  identifies it, and this package enrolls the one and writes the other without
  understanding either.

  Migration: read the members off the token's JSON rather than from typed
  fields. The removed fields were never populated from a real systemd token
  anyway — several named members systemd does not write (#150).
