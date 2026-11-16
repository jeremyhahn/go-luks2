### Security

- **The devcontainer and integration images take Debian's linux-libc-dev
  6.12.117-1.** The base digest moves to the 2026-11-10 golang:1.27.4 rebuild,
  so the base stage's apt-get upgrade runs again instead of reusing a cached
  layer that held linux-libc-dev 6.12.116-1, whose six HIGH CVEs (among them
  CVE-2026-98466) failed trivy image on main c9f8f3be9.
