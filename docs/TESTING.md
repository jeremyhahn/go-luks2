# Testing

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

```bash
make test-unit          # unit tests, -race, per-package coverage profiles
make coverage-gate      # refuse unit coverage below any package's floor
make ci                 # everything CI's fast tier runs, including the above
make integration-test   # integration suite in a scoped container (Docker)
make ci-full            # ci, then the container and the combined coverage gate
```

Unit tests need no root, devices or network. The integration suite needs a real
kernel (loop devices, device-mapper, the kernel keyring, mounts), so it runs in
a container launched by `test/integration/cmd/docker-run`.

## Coverage

Every package is held to 90%, per package and exactly: 89.99% fails, and an
aggregate above 90% does not excuse a package below it. Floors are in
`coverage-floors.txt`; the gate is `test/covergate`.

| Tier | Measured by | Gated in |
|---|---|---|
| `unit` | `make test-unit`: every package from `go list ./...`, default tags, `-race` | CI's unit job and `make ci` |
| `combined` | `make coverage-combined` inside the container: unit plus integration, with `-coverpkg` over `pkg/luks2` and `test/harness` | CI's integration job and `make ci-full` |

`pkg/luks2` and `test/harness` are held to 90% in the combined tier, because
part of each only runs against a real kernel. Each also has a unit floor at its
measured level. Every other package is held to 90% in the unit tier. The gate
also fails on a missing or unreadable profile, a package with no floor, a floor
for a package that no longer exists, and a package held to 90% in no tier.

## Unit runtime and race coverage

`go test -race ./pkg/luks2` has a budget of 240 s on the CI runner
(`UNIT_TEST_TARGET`, printed against the measured time) and a hard ceiling of
10 minutes (`UNIT_TEST_TIMEOUT`). Both are Makefile variables CI reads through
`make test-unit`.

The race detector covers the default-tag build of every package. The
`integration`-tagged tests run in the container without `-race`. `make vet`
vets both the default and `integration` configurations; a new build tag needs
its own vet leg.

## The integration container

`docker run --privileged` grants every capability, disables seccomp and
AppArmor, and exposes the host's whole `/dev`. The suite does not use it. The
narrowest set that was measured to work lives in one place, the `privileges`
function in `test/integration/cmd/docker-run`, and a unit test pins it flag by
flag. Every Makefile target and the CI workflow go through that launcher.

Each row was measured on Linux 6.17 with Docker 29.1.3 by removing that one
item and running the lifecycle the suite performs (loop attach, `luksFormat`,
`luksOpen`, `mkfs.ext4`, `mount`, close, detach):

| Given | Why | First thing that breaks without it |
|---|---|---|
| `--cap-add SYS_ADMIN` | device-mapper ioctls | `luksOpen` (`DM_DEV_CREATE`) |
| `--cap-add MKNOD` | `/dev` is a bare tmpfs; loop and dm nodes are created in it | every `mknod`, `EPERM` |
| `--cap-drop ALL` | nothing else in Docker's default set is used | nothing |
| `--security-opt seccomp=test/integration/seccomp.json` | `add_key`, `keyctl`, `request_key` | every keyring test |
| `--security-opt apparmor=unconfined` | `docker-default` denies `mount(2)` | `mount` |
| `--device /dev/mapper/control` | dm ioctl interface | `dmsetup` and the host-state guard |
| `--device /dev/loop-control` | `LOOP_CTL_GET_FREE` | loop attach |
| `--device-cgroup-rule 'b 7:* rwm'` | opening loop devices | attach, `EPERM` |
| `--device-cgroup-rule "b <dm major>:* rwm"` | opening the mappings created | opening `/dev/mapper/<name>` |

The dm major is read from `/proc/devices` at run time because it is allocated
dynamically; a wrong one yields a container that creates a mapping and cannot
open it.

Seccomp is the constraint, not capabilities. Docker's default profile denies the keyring
syscalls whatever capabilities are added; with the custom profile they work
with none. `test/integration/seccomp.json` is Docker's default profile
(`github.com/moby/profiles/seccomp v0.1.0`) byte for byte plus one allow block
for those three calls. Its header gives the sha256 and how to re-fetch it.
`seccomp=unconfined` would also work and is not used.

AppArmor is off because `docker-default` denies `mount(2)` and loading a
custom profile would mean changing the CI host.

## What the container does not isolate

Device-mapper and loop devices are not namespaced. `dmsetup ls` in the
container lists every mapping on the host, and the cgroup rules allow opening
any loop device and any dm mapping. What keeps the suite off other devices is
`test/harness`: it records every loop device and mapping in a host-side ledger
before creating it, removes only what it recorded, and never sweeps. Treat the
state directory as part of that boundary.

Since #247 the state directory is opened once and checked through that
handle, and every ledger read, lock, write and delete goes through the same
handle. A run's temp root is named `go-luks2-run-<run id>-<n>`, and the reaper
detaches loop devices under a recorded root only when its name carries the id
of the run that recorded it. A ledger from before #247 has a root with no run
id. If loop devices are still backed under it, the reap fails and keeps the
ledger, because they may belong to a live run. Once no integration run is live,
detach them by hand (see below) and delete the ledger.

The entrypoint reaps the previous run's recorded state, then refuses to run if
`dmsetup` is missing, the inventory fails, or a mapping already carries this
container's scope (every name the suite creates is
`<base>-<container scope>-<run id>`). Mappings that belong to the host, such as
an LVM root, or to other containers do not block a run.

## A device no ledger recorded is an operator's job, not this repository's

The reaper removes only what a ledger recorded and only while the live device
still carries the recorded identity. A loop device or mapping that no ledger
names, from an older run, another branch or another process, is cleared by an
operator, one device at a time, after attributing it:

```bash
losetup -a              # find the backing file; attribute the device
losetup -d /dev/loopN   # detach the one you attributed
```

This is policy (owner ruling, 2026-09-22). Ownership is never inferred from
appearance: a path prefix, a deleted backing file or an absence of holders all
match devices that belong to someone else. The refusals in
`test/harness/system.go` and `test/harness/cmd/luks2-testreap` are deliberate.
Do not add a sweep.

## Running part of the suite

```bash
make docker-test-specific TEST=TestSHA1AFVolumesMapTheSameDataOnTheKernel
make integration-test-pkg
make integration-test-cli

# A shell under the suite's privilege set
make docker-run-bin
ITEST_ID=debug make docker-build-integration
IMAGE=go-luks2-integration-test:debug build/docker-run --rm -it -- bash
```

Run the built `build/docker-run`, not `go run`: under `go run` every non-zero
exit status becomes 1.

## Images

Each run builds `go-luks2-integration-test:$(ITEST_ID)` and a matching
container name, so concurrent runs on one host do not collide. Each target
removes its own image and container on exit. Every image carries the label
`go-luks2-itest=1`, and `make docker-prune-itest` (also run before every
integration build and in CI) removes labelled images no container uses that
are older than `ITEST_PRUNE_AGE` (default `2h`). That catches what a `kill -9`
leaves.

To keep an image, name it: `ITEST_ID=debug make docker-build-integration`. It
is still pruned once older than `ITEST_PRUNE_AGE`.
`ITEST_ID`, `ITEST_IMAGE` and `ITEST_CONTAINER` all take their values from the
environment when set.
