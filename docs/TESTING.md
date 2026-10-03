# Testing

Unit tests run anywhere. The integration suite needs a real kernel — loop
devices, device-mapper, the kernel keyring and mounts — so it runs in a
container, and this document is about the privilege that container gets.

```bash
make test-unit            # no devices, no root, no container
make integration-test     # the container, through test/integration/cmd/docker-run
```

The container's default command is `make coverage-combined`: the integration
suite, instrumenting `pkg/luks2` and `test/harness`, then the unit suite for
those two packages, then the coverage gate over the union of both profiles. A
package below its combined floor fails the container and with it the run --
the README's "Coverage, and how it is measured" says which packages are gated
in which tier, and why.

## The container is not privileged

`docker run --privileged` is not a privilege setting. It is the absence of
every restriction Docker has: all capabilities, seccomp off, AppArmor off, and
the host's entire `/dev` bind-mounted in. On the machine where this was
measured that meant the test container could open the root NVMe, an unrelated
RAID array and every device-mapper mapping on the box.

This library holds volume keys for a trusted computing platform, and a test rig
is not where that gets handed away for convenience (owner direction,
2026-08-31; issue #80). The suite runs under the narrowest set that was
measured to work, and that set lives in exactly one place: the `privileges`
function in

**`test/integration/cmd/docker-run`.**

A unit test pins it flag by flag, so adding or dropping one fails `make test-unit`.

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

## A device no ledger recorded is an operator's job, not this repository's

The reaper removes what a ledger recorded, where the live resource still
carries the recorded identity. A loop device or mapping that **no ledger
names** — left by a run from before the ledger existed, by a branch that does
not ship the harness, or by some other process entirely — is outside its reach,
permanently and by design.

**Owner ruling, 2026-09-22 (issue #114): an operator clears such a device by
hand, per device, on positive attribution, using the stock tools.** There is no
command in this repository for it and none is wanted:

```bash
losetup -a              # read the backing file, attribute the device to a run
losetup -d /dev/loopN   # detach the one you attributed
```

The reasoning, so nobody re-opens it from first principles:

- **Ownership is never inferred from a device's appearance.** Not "it matches
  `/tmp/go-luks2-run-*`" — a developer's directory can too. Not "its backing
  file is `(deleted)`" — so is any unlinked image on the box. Not "nothing
  holds it" — measured on a LIVE job's device 2026-09-01, `holders` and `fuser`
  were both empty and the only distinguishing fact was that a job owned it.
- **A sweep is worst at exactly the cases that cost.** It matches the
  well-behaved leftovers, which already carry this suite's metadata and which
  the record-based reaper reclaims unaided; it misses the ones left by code
  that never knew the ledger existed. Measured on the six orphans that
  exhausted a runner's eight-minor loop pool on 2026-09-02, five were backed
  directly under `/tmp/` and not under any run root — a bounded-by-prefix sweep
  would have matched none of them. Risk bought in exchange for covering the
  cases you did not need covered.
- **The inflow is already closed producer-side.** The suite records every loop
  device and mapping before creating it and fails the run if it cannot, so the
  unrecorded set is finite and historical rather than growing. Clearing it is
  an operational action on the named hosts, tracked by Infrastructure.
- **Shipping an operator command here would not help and would decay.** `losetup`
  is already on every runner; a tool in this tree adds nothing but proximity to
  the suite, and that is what later grows an `--all` flag and re-lands PR #85's
  `losetup -D` / `dmsetup remove_all` under a new spelling.

So the "no sweep, no prefix match, no looks-like-ours" refusals in
`test/harness/system.go` and `test/harness/cmd/luks2-testreap` are **policy,
not an omission**. Removing one is an owner decision, not a cleanup.

Container scoping does not substitute for any of this: loop and dm are not
namespaced, so #80 reduced this suite's reach without removing its ability to
create host loop state — see "What scoping the container does *not* do" above.

## Running a single test

```bash
make docker-test-specific TEST=TestLoopDeviceCleanup
make integration-test-pkg
make integration-test-cli
```

All three go through `test/integration/cmd/docker-run`. To get an interactive
shell under the same privilege the suite runs with — which is the point, a
shell that behaves like the suite rather than like a machine with no
restrictions:

```bash
make docker-run-bin
build/docker-run --rm -it -- bash
```

Run the built binary, not `go run`: the launcher execs docker in place so
docker's exit status comes back unchanged, but under `go run` the go tool stays
the parent and reports every nonzero status as 1.

## Image names, and what removes them

Every integration run builds its image under a tag unique to that invocation —
`go-luks2-integration-test:$(ITEST_ID)` — and runs its container under a
matching name. That is what keeps two runs on one host from killing each
other's containers or swapping each other's images mid-suite (#105). It also
means nothing is ever *replaced*, so something has to delete:

- Each target that runs the suite removes its own image and container from a
  trap, on success and on failure alike.
- A build that is the whole job — `make docker-build-integration` with nothing
  after it — removes what it built. No later run can name that tag, so keeping
  it is only disk. The BuildKit layer cache, which is the reason to pre-build
  at all, is stored separately and survives.
- Everything else is caught by the label. Every image built here carries
  `go-luks2-itest=1`, and `make docker-prune-itest` — which also runs at the
  start of every integration build, and in CI — removes labelled images that no
  container references and that are older than `ITEST_PRUNE_AGE` (default
  `2h`). This is the only mechanism that survives a `kill -9`, where no trap
  runs at all.

The age floor is not a guess: `prune` already skips an image any container
references, so a suite that is executing is safe, but the seconds between
another run's `docker build` and its `docker run` are not covered by that, and
deleting an image inside that window fails the other run with `Unable to find
image locally`. An hours-wide floor cannot land in a seconds-wide window.

To keep an image — to poke at it by hand, or to build once and run later — name
it yourself:

```bash
export ITEST_ID=debug          # or ITEST_IMAGE=my-image:debug
make docker-build-integration  # builds go-luks2-integration-test:debug, keeps it
```

A kept image still carries the label — everything built here does, or the reaper
would have holes exactly where the orphans are — so one left unused is collected
once it is older than `ITEST_PRUNE_AGE`. Raise that value if you need it for
longer than a couple of hours.

`ITEST_ID`, `ITEST_IMAGE` and `ITEST_CONTAINER` all defer to the environment, so
a caller that has already decided the names — CI does, per job attempt — gets
the names it chose, and its own cleanup matches what was actually created.
