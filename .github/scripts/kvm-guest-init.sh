#!/bin/bash
# The first and only process of the KVM guest of prune-kvm.yml: it lays out the prune container's mounts
# from the data disk, runs the audit observer, tells the host how it went and powers the guest off.
#
# The host puts this file into the root file system it exports from the prune image and boots the guest
# with init=/phobos-kvm-init, root=/dev/vda and the data disk on /dev/vdb. phobos_key=<key> on the kernel
# command line names the key to verify. The data disk holds exercises/, helpers/, path_sets/ (the
# artefacts of the default prune, which this run reads and adds to), setup.sh and env.sh, as
# stage-prune-inputs.sh made them. What the guest writes to the serial console is the host's log; the
# line "PHOBOS-KVM-STATUS <n>" is the status of the observer and the last thing printed before power off.
set -u

# The status the guest reports when it could not even start the observer.
readonly EXIT_SETUP=70

# Prints the value of one key=value word of the kernel command line, or nothing.
cmdline_value() {
  local word
  for word in $(cat /proc/cmdline); do
    [[ "${word}" == "$1="* ]] && { printf '%s' "${word#*=}"; return 0; }
  done
  return 0
}

# Ends the guest: the status line first, then everything written, then power off.
finish() {
  printf 'PHOBOS-KVM-STATUS %s\n' "$1"
  sync
  umount /var/tmp/path_sets 2>/dev/null
  umount /mnt/data 2>/dev/null
  sync
  echo o > /proc/sysrq-trigger
  sleep 60
}

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null

KEY="$(cmdline_value phobos_key)"
[[ -n "${KEY}" ]] || { echo "no phobos_key on the kernel command line"; finish "${EXIT_SETUP}"; }

mkdir -p /mnt/data /srv/phobos-prune-exercises /var/tmp/helpers /var/tmp/path_sets
mount /dev/vdb /mnt/data || { echo "the data disk cannot be mounted"; finish "${EXIT_SETUP}"; }
mount --bind /mnt/data/exercises /srv/phobos-prune-exercises
mount --bind /mnt/data/helpers /var/tmp/helpers
mount --bind /mnt/data/path_sets /var/tmp/path_sets
# Loopback is the only network, as the prune container's --network none leaves it.
ip link set lo up 2>/dev/null || python3 -c 'import fcntl, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
flags = struct.unpack("16sH", fcntl.ioctl(s, 0x8913, struct.pack("16sH", b"lo", 0)))[1]
fcntl.ioctl(s, 0x8914, struct.pack("16sH", b"lo", flags | 1))'

export PHOBOS_HOME=/var/tmp/opt/core
export PHOBOS_PRUNE_CONTAINER=1
export PATH="${PHOBOS_HOME}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME=/root
# shellcheck disable=SC1091
source /mnt/data/env.sh
# shellcheck disable=SC1091
source /mnt/data/setup.sh

printf 'PHOBOS-KVM-KERNEL %s\n' "$(uname -r)"
python3 /var/tmp/helpers/layer_prune/main.py --kernel-observer audit --output-dir /var/tmp/path_sets "${KEY}"
status=$?
# What the kernel wrote, for whoever reads the run: the records that replace the fixtures' written ones.
dmesg | grep -E 'type=(1423|1424|LANDLOCK)' > /var/tmp/path_sets/audit-raw.log
finish "${status}"
