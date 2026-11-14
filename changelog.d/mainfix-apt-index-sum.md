### Security

- **The integration image tracks the Debian package index.** `make -s
  apt-index-sum` hashes the base image's live Debian index; CI puts it in
  APT_INDEX_SUM, which the integration image's content tag hashes and whose
  build argument the integration stage declares before its own `apt-get
  upgrade`. A Debian security fix now renames the image and re-runs that
  upgrade, where before a cached base upgrade layer kept the old packages: main
  9ab065b04 still shipped linux-libc-dev 6.12.116-1 under a new base digest.
