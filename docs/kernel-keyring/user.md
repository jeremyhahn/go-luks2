# Kernel keyring — user guide

> **Status: NORMATIVE** · Last verified: 2026-10-11 against main (f871541)
> Conflicts with this document are defects. Fix them here first.

When you unlock a volume, the key is handed to the kernel through its keyring
rather than written into the device-mapper table. You do not configure this; it
either works or tells you what to change.

## Prerequisites

- A Linux kernel built with keyring support (`CONFIG_KEYS`).
- Inside a container, the `add_key`, `keyctl` and `request_key` syscalls
  allowed by the seccomp profile. Docker's default profile denies them, and
  `--cap-add SYS_ADMIN` does not change that.

## First run

```bash
sudo luks2 open /dev/sdb1 backup
```

If it succeeds, the keyring is working. A program using the library can check
at startup, before it takes any work, with `dmcrypt.CheckKeyring`; see
[api.md](api.md).

## Common tasks

**Run in Docker.** Use a profile that is Docker's default plus an allow rule for
the three syscalls:

```bash
docker run --security-opt seccomp=/path/to/profile.json …
```

Prefer a narrow profile over `--security-opt seccomp=unconfined`, which also
drops every other syscall restriction. Under Kubernetes, use a localhost
profile in `securityContext.seccompProfile`.

**Check a service before it takes traffic.** Call `dmcrypt.CheckKeyring` during
initialization and refuse to start on error. The error names the cause and the
fix.

## Troubleshooting

| What you see | Cause | What to do |
|---|---|---|
| `kernel keyring` and a seccomp remedy | The syscalls are blocked by policy | Allow `add_key`, `keyctl` and `request_key` in the container's seccomp profile |
| `kernel keyring` and `CONFIG_KEYS` | The kernel has no keyring support | Use a kernel that has it. There is no workaround and no fallback |
| `kernel keyring` and a quota remedy | The per-user key quota is full | Raise `/proc/sys/kernel/keys/maxkeys` and `maxbytes` (`root_maxkeys` and `root_maxbytes` for root), or find what is holding keys with `keyctl show` |
| `kernel keyring` and "refused the operation" | The syscalls work and the kernel said no | The error carries the kernel's own reason |
| An entry "already exists" for this volume | A key from an earlier run is still in the keyring, for example after a crash | Remove it with the `keyctl unlink` command the message prints, then retry |
| A key "may still be present" | The key could not be confirmed removed after the open | Run the `keyctl show` and `keyctl unlink` commands the message prints |
