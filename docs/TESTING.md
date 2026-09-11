# Testing

Unit tests run anywhere. The integration suite needs a real kernel — loop
devices, device-mapper, the kernel keyring and mounts — so it runs in a
container, and this document is about the privilege that container gets.

```bash
make test-unit            # no devices, no root, no container
make integration-test     # the container, through test/integration/docker-run.sh
```

## The container is not privileged

`docker run --privileged` is not a privilege setting. It is the absence of
every restriction Docker has: all capabilities, seccomp off, AppArmor off, and
the host's entire `/dev` bind-mounted in. On the machine where this was
measured that meant the test container could open the root NVMe, an unrelated
RAID array and every device-mapper mapping on the box.

This library holds volume keys for a trusted computing platform, and a test rig
is not where that gets handed away for convenience (owner direction,
2026-08-31; issue #80). The suite runs under the narrowest set that was
measured to work, and that set lives in exactly one file:

**`test/integration/docker-run.sh`.**

Every Makefile target and the CI workflow call it. Nothing else spells out a
privilege flag, because five copies of a security-critical invocation is how
one of them quietly grows a flag the others do not have.

## What the container gets, and what happens without it

Each row was measured on Linux 6.17 with Docker 29.1.3, by removing exactly
that one thing from the working invocation and running the LUKS lifecycle the
suite performs: attach a file-backed loop device, `luksFormat`, `luksOpen`,
`mkfs.ext4`, `mount`, `close`, detach.

| Given | Why | First thing that breaks without it |
|---|---|---|
| `--cap-add SYS_ADMIN` | the device-mapper ioctl interface | `luksOpen` — loop attach and `luksFormat` still succeed, `DM_DEV_CREATE` fails |
| `--cap-add MKNOD` | `/dev` is a bare tmpfs; the loop and dm nodes are created in it | every `mknod`, with `EPERM`, before anything else runs |
| `--cap-drop ALL` | nothing else in Docker's default set is used | nothing — the full lifecycle completes with the two capabilities above and no others |
| `--security-opt seccomp=test/integration/seccomp.json` | `add_key`, `keyctl`, `request_key` | every keyring test, with `operation not permitted` |
| `--security-opt apparmor=unconfined` | `docker-default` denies `mount(2)` | `mount` — `mkfs.ext4` succeeds first, then "cannot mount read-only" |
| `--device /dev/mapper/control` | the dm ioctl interface | `dmsetup`, and with it the host-state guard, which fails closed |
| `--device /dev/loop-control` | `LOOP_CTL_GET_FREE`, which is how `SetupLoopDevice` picks a device | loop attach: "cannot find an unused loop device: No such device" |
| `--device-cgroup-rule 'b 7:* rwm'` | *opening* the loop device, which the cgroup filter gates separately from creating its node | attach, with `EPERM` — the `mknod` still succeeds, so the node is there and unusable |
| `--device-cgroup-rule "b <dm major>:* rwm"` | opening the mappings created | `/dev/mapper/<name>`: "open failed: Operation not permitted", right after the mapping is made |

The dm major is read from `/proc/devices` at run time — it is allocated
dynamically at module load (252 on one machine here, 253 on plenty of others),
and a hard-coded one does not fail loudly, it produces a container that creates
a mapping and then cannot open it.

Two capabilities. Two device nodes. Two block majors. That is the whole set.
The root NVMe, the SATA disks, the md arrays and the TPM — every one of which
`--privileged` handed over — are not reachable from inside at all.

### Capabilities were the wrong suspect

The intuition is that a container needs `CAP_SYS_ADMIN` to touch the kernel
keyring. It does not, and measuring it was the thing that unstuck this:

| Environment | `add_key` |
|---|---|
| host, unprivileged (uid 1000) | **OK** |
| container, default seccomp, no capabilities added | **FAILS** |
| container, default seccomp, `--cap-add SYS_ADMIN` | **FAILS** |
| container, `test/integration/seccomp.json`, **no capabilities added** | **OK** |
| container, `--security-opt seccomp=unconfined` | **OK** |
| container, `--privileged` | **OK** |

Kernel keyrings are not namespaced, so Docker's default profile denies
`add_key`, `keyctl` and `request_key` outright — they appear in no allow block
and fall through to `defaultAction`. No capability lifts a seccomp denial, and
no capability is needed once seccomp allows the call.

### The seccomp profile

`test/integration/seccomp.json` is Docker's default profile **byte for byte**,
plus one appended allow block naming those three syscalls. Upstream is
`default.json` from `github.com/moby/profiles/seccomp v0.1.0` — the version the
local daemon links, which `go version -m $(which dockerd)` will tell you. The
file's own header carries the sha256 and the re-fetch command, and keeping the
upstream text untouched is the point: the only thing a reviewer has to read is
the diff.

`seccomp=unconfined` would also make the suite pass, and is not used. It
re-admits every syscall the default profile denies — the `mount`, `kexec`,
`bpf` and namespace calls the profile exists to keep away from a container — to
solve a three-syscall problem.

### AppArmor is the one real loss

`docker-default` denies `mount(2)` unconditionally and the suite mounts the
filesystems it creates inside the unlocked mapping, so the profile is turned
off. The alternative — shipping `docker-default` plus a mount rule — means
loading a profile into the **host** kernel with `apparmor_parser` before the
suite can run, and this repository does not mutate a CI runner in order to test
itself. Worth revisiting if the runners grow a managed profile.

## What scoping the container does *not* do

Device-mapper and loop devices are **not namespaced**. There is one dm
subsystem and one loop subsystem per kernel, and a container has no view of its
own.

- `dmsetup ls` inside the scoped container lists **every mapping on the
  machine**, exactly as it did under `--privileged`. `DM_LIST_DEVICES` is an
  ioctl on `/dev/mapper/control` and returns the global list regardless of
  which `/dev` entries the container was given. No flag filters it — not
  `--device`, not a device-cgroup rule, not a user namespace.
- The two `--device-cgroup-rule` lines permit opening **any** dm mapping and
  **any** loop device on the host, not only the ones this suite created. Both
  kernels allocate minors dynamically, so neither rule can be pinned to the
  minors a given run happens to get, and Docker's rule syntax has no range
  form.

So the scoped invocation is a large reduction in reach — from every device of
every kind down to two majors — and it is **not isolation**. What keeps this
suite off other people's devices is `test/harness`: it records every loop
device and mapping in a host-side ledger *before* creating it, removes only
what it recorded, and never sweeps. Read `test/harness` before changing
anything about the state directory; it is part of the trust boundary, not a
cache.

## The host-state guard

The image's entrypoint reaps the previous run's recorded state, then refuses to
run if `dmsetup ls` reports any mapping at all:

```
REFUSING TO RUN: the host device-mapper is visible from this
container and already has mappings this suite did not create:
...
```

Because dm is not namespaced, this guard passes only on a host with **no dm
mappings whatsoever** — a machine with an LVM root will always trip it, with or
without `--privileged`. Scoping the container's device access does not and
cannot change that.

## Running a single test

```bash
make docker-test-specific TEST=TestLoopDeviceCleanup
make integration-test-pkg
make integration-test-cli
```

All three go through `test/integration/docker-run.sh`. To get an interactive
shell under the same privilege the suite runs with — which is the point, a
shell that behaves like the suite rather than like a machine with no
restrictions:

```bash
test/integration/docker-run.sh --rm -it -- bash
```
