#!/usr/bin/env bash
# Boots the KVM guest of prune-kvm.yml and runs the audit observer in it (prune plan A.6.9).
#
#   run-prune-in-kvm-guest.sh <image> <kernel bzImage> <inputs directory> <path_sets directory> <key>
#
# <image> is the prune image, whose root file system the guest runs on, so that the same layers, the same
# enforcers and the same helpers run on the newer kernel. <inputs directory> is what stage-prune-inputs.sh
# staged and <path_sets directory> the artefacts of the default prune, which the guest reads and adds its
# .abi10 files to; they are copied onto a data disk and the result copied back, so the guest has no
# network card, no shared directory and no way to reach the host.
#
# It asserts first, through tests/runner-capability-probe.sh --assert-kvm, that a guest boots under KVM at
# all, and ends with status 3 where that cannot be told or the guest could not observe Landlock's audit
# records (the observer's own status 3), never with a pass. The guest's console log is kept in the path_sets
# directory as kvm-console.log. Needs qemu-system-x86, e2fsprogs and sudo without a password.
set -euo pipefail

# The status this script ends with when it was called the wrong way, and when no verdict can be given.
readonly EXIT_USAGE=2
readonly EXIT_INDETERMINATE=3
# How long the guest may run, its memory and its virtual CPUs; the free space the root disk gets beyond the image.
readonly GUEST_SECONDS=14400
readonly GUEST_MEMORY_MB=6144
readonly GUEST_CPUS=2
readonly ROOT_SLACK_MB=2048
readonly DATA_DISK_MB=1024

[[ $# -eq 5 ]] || { printf 'usage: run-prune-in-kvm-guest.sh <image> <kernel> <inputs> <path_sets> <key>\n' >&2; exit "${EXIT_USAGE}"; }
IMAGE="$1"
KERNEL="$2"
INPUTS="$3"
PATH_SETS="$4"
KEY="$5"
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY="$(cd -- "${HERE}/../.." && pwd)"
WORK="$(mktemp -d)"
CONTAINER="phobos-kvm-root-$$"

# Removes what the run made, however it ends.
cleanup() {
  docker rm -f "${CONTAINER}" > /dev/null 2>&1 || true
  sudo rm -rf "${WORK}"
}
trap cleanup EXIT

if ! bash "${REPOSITORY}/tests/runner-capability-probe.sh" --assert-kvm; then
  printf 'no guest boots under KVM here, so this run answers nothing\n' >&2
  exit "${EXIT_INDETERMINATE}"
fi

# The root file system of the guest: the prune image as docker exports it, owned as it is in the image,
# with the init the guest runs.
mkdir -p "${WORK}/root"
docker create --name "${CONTAINER}" "${IMAGE}" /bin/true > /dev/null
docker export "${CONTAINER}" | sudo tar -x -C "${WORK}/root" --numeric-owner
sudo install -m 0755 "${HERE}/kvm-guest-init.sh" "${WORK}/root/phobos-kvm-init"
# What an export of the image leaves out: the environment it declares, for the init to source, and the
# file the observer is refused a read of after every run.
docker inspect --format '{{range .Config.Env}}export {{printf "%q" .}}{{"\n"}}{{end}}' "${IMAGE}" \
  | sudo tee "${WORK}/root/etc/phobos-image-env" > /dev/null
sudo touch "${WORK}/root/etc/phobos-kvm-sentinel"
sudo mkdir -p "${WORK}/root/mnt/data" "${WORK}/root/proc" "${WORK}/root/sys" "${WORK}/root/dev" "${WORK}/root/tmp" "${WORK}/root/run"
root_mb="$(sudo du -sm "${WORK}/root" | cut -f1)"
truncate -s "$(( root_mb + ROOT_SLACK_MB ))M" "${WORK}/root.img"
sudo mkfs.ext4 -q -F -i 8192 -d "${WORK}/root" "${WORK}/root.img"
sudo rm -rf "${WORK}/root"

# The data disk: what the guest mounts as the prune container's volumes.
mkdir -p "${WORK}/data"
cp -R "${INPUTS}/exercises" "${INPUTS}/helpers" "${INPUTS}/setup.sh" "${INPUTS}/env.sh" "${WORK}/data/"
mkdir -p "${WORK}/data/path_sets"
cp -R "${PATH_SETS}/." "${WORK}/data/path_sets/"
truncate -s "${DATA_DISK_MB}M" "${WORK}/data.img"
mkfs.ext4 -q -F -d "${WORK}/data" "${WORK}/data.img"

# KVM needs the device; where the user cannot open it, QEMU runs under sudo.
runner=()
if [[ ! ( -r /dev/kvm && -w /dev/kvm ) ]]; then
  runner=(sudo -n)
fi
# The kernel is told: Landlock first in the LSM list, audit on with a backlog and a message ring large
# enough for every record of a prune, a serial console, and the key to verify.
set +e
timeout "${GUEST_SECONDS}" "${runner[@]}" qemu-system-x86_64 -machine q35,accel=kvm -cpu host \
  -smp "${GUEST_CPUS}" -m "${GUEST_MEMORY_MB}" -nographic -no-reboot -nic none -kernel "${KERNEL}" \
  -drive "file=${WORK}/root.img,format=raw,if=virtio" -drive "file=${WORK}/data.img,format=raw,if=virtio" \
  -append "console=ttyS0 root=/dev/vda rw rootfstype=ext4 init=/phobos-kvm-init lsm=landlock,lockdown,yama,integrity audit=1 audit_backlog_limit=65536 log_buf_len=64M printk.devkmsg=on loglevel=4 panic=-1 phobos_key=${KEY}" \
  > "${WORK}/console.log" 2>&1
qemu_status=$?
set -e

# What the guest wrote, whether or not it finished: the artefacts it added and its console.
mkdir -p "${PATH_SETS}"
cp "${WORK}/console.log" "${PATH_SETS}/kvm-console.log"
e2fsck -fp "${WORK}/data.img" > "${WORK}/fsck.log" 2>&1 || { printf 'the data disk needed repair:\n' >&2; cat "${WORK}/fsck.log" >&2; }
if ! debugfs -R "rdump /path_sets ${WORK}" "${WORK}/data.img" > "${WORK}/rdump.log" 2>&1 || [[ ! -d "${WORK}/path_sets" ]]; then
  printf 'the artefacts could not be read back from the data disk:\n' >&2
  cat "${WORK}/rdump.log" >&2
  exit "${EXIT_INDETERMINATE}"
fi
cp -R "${WORK}/path_sets/." "${PATH_SETS}/"

# The serial console ends its lines with a carriage return, and a kernel message can sit before the word.
status_line="$(grep -a 'PHOBOS-KVM-STATUS [0-9]' "${WORK}/console.log" | tail -1 | tr -d '\r' || true)"
if [[ -z "${status_line}" ]]; then
  printf 'the guest ended without reporting (QEMU status %s); the last lines of its console:\n' "${qemu_status}" >&2
  tail -20 "${WORK}/console.log" >&2
  exit "${EXIT_INDETERMINATE}"
fi
grep -a '^PHOBOS-KVM-KERNEL ' "${WORK}/console.log" || true
status="${status_line##*PHOBOS-KVM-STATUS }"
if [[ ! "${status}" =~ ^[0-9]+$ ]]; then
  printf 'the guest reported a status that is not a number: %s\n' "${status_line}" >&2
  exit "${EXIT_INDETERMINATE}"
fi
printf 'the observer in the guest ended with status %s\n' "${status}"
if [[ "${status}" -eq 0 ]]; then
  # A pass needs a record for every exercise the default prune wrote a policy for.
  missing=0
  for cfg in "${PATH_SETS}/${KEY}"_*.cfg; do
    case "${cfg}" in *.abi10.cfg) continue ;; esac
    [[ -f "${cfg%.cfg}.abi10.json" ]] || { printf 'no KVM record beside %s\n' "${cfg}" >&2; missing=1; }
  done
  [[ "${missing}" -eq 0 ]] || exit "${EXIT_INDETERMINATE}"
fi
exit "${status}"
