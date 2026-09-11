#!/usr/bin/env bash
#
# The one place the integration container's privilege set is written down.
#
# It used to be `docker run --privileged`, in five places -- four Makefile
# targets and the CI workflow -- which is how a security-critical invocation
# drifts. --privileged is not a privilege: it is the absence of every
# restriction Docker has. All capabilities, seccomp off, AppArmor off, and the
# whole host /dev bind-mounted in, which on the machine this was measured on
# meant the container could open the root NVMe, an unrelated RAID array and
# every dm mapping on the box. This library holds volume keys for a trusted computing
# platform (owner direction, 2026-08-31), and a test rig is not where that gets
# handed away for convenience.
#
# Every flag below was MEASURED, not assumed. docs/TESTING.md carries the table
# of what fails when each one is removed; the reasons are repeated at each flag
# because that is where someone deletes one.
#
# Usage:
#
#	test/integration/docker-run.sh [docker flags ...] -- [command ...]
#
# Flags before `--` go to `docker run`; everything after it is the command for
# the container, and an empty command runs the image's default (the whole suite
# with coverage). The `--` is mandatory so neither list can swallow the other.
#
#	test/integration/docker-run.sh --rm -- go test -tags=integration ./...
#	test/integration/docker-run.sh --name go-luks2-test-runner --
#
# Environment:
#
#	TEST_STATE_DIR  host directory holding the run ledgers, bind-mounted in.
#	                Read test/harness before changing it: it is part of the
#	                trust boundary, not a cache.
#	IMAGE           image to run.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${TEST_STATE_DIR:-/var/tmp/go-luks2-test-state}"
image="${IMAGE:-go-luks2-integration-test}"

docker_flags=()
while [ "$#" -gt 0 ]; do
	if [ "$1" = "--" ]; then
		shift
		break
	fi
	docker_flags+=("$1")
	shift
done

# The device-mapper major is allocated dynamically at module load -- 252 on the
# machine this was written on, 253 on plenty of others. Read it rather than
# hard-code it: a wrong major does not fail loudly here, it produces a
# container that creates a mapping and then cannot open it.
dm_major="$(awk '$2 == "device-mapper" { print $1 }' /proc/devices)"
if [ -z "${dm_major}" ]; then
	echo "REFUSING TO RUN: there is no device-mapper major in /proc/devices, so" >&2
	echo "dm is not available on this host and the suite cannot create a" >&2
	echo "mapping. Load the module (modprobe dm_mod) and try again." >&2
	exit 1
fi

privileges=(
	# CAP_SYS_ADMIN -- for device-mapper, and for nothing else here.
	# MEASURED: with everything else below in place but the default
	# capability set, loop attach and luksFormat both succeed and luksOpen
	# fails; DM_DEV_CREATE is the ioctl that needs it. There is no narrower
	# capability to ask for -- the kernel gates the entire dm ioctl
	# interface on CAP_SYS_ADMIN.
	--cap-add SYS_ADMIN

	# CAP_MKNOD -- to create nodes for what we allocate. /dev in an
	# unprivileged container is a bare tmpfs, so nothing creates /dev/loopN
	# or /dev/dm-N for us: the entrypoint makes the loop nodes and pkg/luks2
	# mknods the dm nodes itself, which is the fallback unlock.go has always
	# carried for udev-less environments. MEASURED: without it every mknod
	# returns EPERM and nothing past the first step runs.
	#
	# It is in Docker's DEFAULT set already. It is named here because the
	# --cap-drop ALL below takes it away, not because it is an escalation.
	--cap-add MKNOD

	# Everything else goes. Docker's default set -- CHOWN, DAC_OVERRIDE,
	# FOWNER, NET_RAW, SETUID, SETGID and the rest -- buys a suite that runs
	# as root against files it created nothing. MEASURED: the full lifecycle
	# (loop attach, luksFormat, luksOpen, mkfs, mount, close, detach)
	# completes with exactly these two capabilities and no others.
	--cap-drop ALL

	# The three keyring syscalls, and only those, on top of Docker's default
	# seccomp profile. Kernel keyrings are not namespaced, so the default
	# profile denies add_key, keyctl and request_key outright; pkg/luks2
	# stores volume keys as logon keys and the suite exercises that against
	# the real kernel. MEASURED: no capability substitutes for this --
	# add_key fails under the default profile even with CAP_SYS_ADMIN, and
	# succeeds under this profile with no capabilities added at all. The
	# file is Docker's own profile byte for byte with one block appended;
	# its header says where it came from and how to re-verify it.
	--security-opt "seccomp=${here}/seccomp.json"

	# AppArmor off -- and unlike the rest of this list, that is a loss, not
	# a tightening. The docker-default profile denies mount(2) outright and
	# the suite mounts the filesystems it makes inside the unlocked mapping.
	# MEASURED: with docker-default enforcing, everything through mkfs.ext4
	# succeeds and mount fails with "cannot mount read-only". The
	# alternative -- shipping docker-default plus a mount rule -- means
	# loading a profile into the HOST kernel with apparmor_parser before the
	# suite can run, and this repository does not mutate a CI runner to test
	# itself. Worth revisiting if the runners ever grow a managed profile.
	--security-opt apparmor=unconfined

	# Two control nodes, instead of the host's entire /dev.
	# /dev/mapper/control is the dm ioctl interface; /dev/loop-control
	# answers LOOP_CTL_GET_FREE. Both are character devices that hand out
	# block devices, and they are the only two entries from the host that
	# the container gets. The root NVMe, the SATA disks, the md arrays and
	# the TPM -- every one of which --privileged handed over -- are not
	# reachable from in here at all.
	--device /dev/mapper/control
	--device /dev/loop-control

	# The block majors the suite allocates from: 7 is LOOP_MAJOR, fixed
	# kernel ABI; the dm major was read from /proc/devices above. A node is
	# useless without a cgroup rule permitting its major:minor -- MEASURED,
	# the mknod still succeeds without the rule and the open that follows
	# returns EPERM, which is the confusing half of this and the reason both
	# rules are here rather than just the capability. Both kernels allocate
	# their minors dynamically, so neither rule can be pinned to the minors
	# a given run happens to get, and Docker's rule syntax has no range form
	# either.
	#
	# BE CLEAR ABOUT WHAT THIS DOES NOT DO. It permits opening any dm
	# mapping and any loop device on the host, including ones the suite did
	# not create, because device-mapper and loop are not namespaced and
	# nothing at the container boundary can make them so. It is a large
	# reduction from --privileged, which permitted every device of every
	# kind, and it is NOT isolation. What keeps this suite off other
	# people's devices is the harness: it records what it creates, removes
	# only what it recorded, and never sweeps.
	--device-cgroup-rule 'b 7:* rwm'
	--device-cgroup-rule "b ${dm_major}:* rwm"

	# The run ledgers, on the HOST. A record kept inside the container dies
	# with the run it describes, which is the one run whose host state needs
	# removing. See test/harness and test/integration/Dockerfile.
	-v "${state_dir}:/var/lib/go-luks2-test-state"
)

exec docker run "${docker_flags[@]}" "${privileges[@]}" "${image}" "$@"
