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
# The open-file limit a container of the prune would give its processes, which a guest's init does not.
readonly OPEN_FILES=1048576

# Prints the value of one key=value word of the kernel command line, or nothing.
cmdline_value() {
  local word
  for word in $(cat /proc/cmdline); do
    [[ "${word}" == "$1="* ]] && { printf '%s' "${word#*=}"; return 0; }
  done
  return 0
}

# Ends the guest: the status line first, then everything written, then power off. The data disk is
# unmounted after the three directories bound from it, which would otherwise keep it busy.
finish() {
  printf 'PHOBOS-KVM-STATUS %s\n' "$1"
  sync
  umount /var/tmp/path_sets 2>/dev/null
  umount /var/tmp/helpers 2>/dev/null
  umount /srv/phobos-prune-exercises 2>/dev/null
  umount /mnt/data 2>/dev/null
  sync
  echo o > /proc/sysrq-trigger
  sleep 60
  exit "$1"
}

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
# What a container has under /dev and a bare devtmpfs does not: the descriptor links the shell's process
# substitution goes through, the pseudo-terminal devices and shared memory.
ln -sfn /proc/self/fd /dev/fd
ln -sfn /proc/self/fd/0 /dev/stdin
ln -sfn /proc/self/fd/1 /dev/stdout
ln -sfn /proc/self/fd/2 /dev/stderr
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
ln -sfn pts/ptmx /dev/ptmx
mount -t tmpfs tmpfs /dev/shm
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null
# Audit records reach the message ring through a rate limit by default (ten in five seconds), which would
# drop most of what a run provokes; the observer ends as indeterminate when it sees a record go missing.
echo 0 > /proc/sys/kernel/printk_ratelimit
ulimit -n "${OPEN_FILES}" 2>/dev/null

KEY="$(cmdline_value phobos_key)"
[[ -n "${KEY}" ]] || { echo "no phobos_key on the kernel command line"; finish "${EXIT_SETUP}"; }

mkdir -p /mnt/data /srv/phobos-prune-exercises /var/tmp/helpers /var/tmp/path_sets /var/tmp/testing-dir
mount /dev/vdb /mnt/data || { echo "the data disk cannot be mounted"; finish "${EXIT_SETUP}"; }
mount --bind /mnt/data/exercises /srv/phobos-prune-exercises
mount --bind /mnt/data/helpers /var/tmp/helpers
mount --bind /mnt/data/path_sets /var/tmp/path_sets
# Loopback is the only network, as the prune container's --network none leaves it.
ip link set lo up 2>/dev/null || python3 -c 'import fcntl, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
flags = struct.unpack("16sH", fcntl.ioctl(s, 0x8913, struct.pack("16sH", b"lo", 0)))[1]
fcntl.ioctl(s, 0x8914, struct.pack("16sH", b"lo", flags | 1))'

# The environment the image declares, which an exported root file system does not carry, then the
# variables the prune needs. The kernel is asked, through PHOBOS_LANDLOCK_LOG_NEW_EXEC, to log what the
# command is refused, which it does for a program that restricts itself and then execs only on request.
if [[ -f /etc/phobos-image-env ]]; then
  # shellcheck disable=SC1091
  source /etc/phobos-image-env
fi
export PHOBOS_HOME=/var/tmp/opt/core
export PHOBOS_PRUNE_CONTAINER=1
export PHOBOS_LANDLOCK_LOG_NEW_EXEC=1
export PATH="${PHOBOS_HOME}:${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
export HOME=/root
# shellcheck disable=SC1091
source /mnt/data/env.sh
# shellcheck disable=SC1091
source /mnt/data/setup.sh

# What the guest finds out about the kernel before the observer starts: printed to the console, where the
# host keeps it, so that a guest that cannot see Landlock's records says what it did see.
diagnose() {
  printf 'PHOBOS-KVM-DIAG cmdline: %s\n' "$(cat /proc/cmdline)"
  printf 'PHOBOS-KVM-DIAG printk: %s / ratelimit %s\n' "$(cat /proc/sys/kernel/printk)" \
    "$(cat /proc/sys/kernel/printk_ratelimit)"
  dmesg | grep -i -E 'audit|landlock|LSM' | head -20 | sed 's/^/PHOBOS-KVM-DIAG boot: /'
  printf '[read]\n/usr/local/libexec/phobos-prune-probe\n/dev/null\n\n[execute]\n/usr/local/libexec/phobos-prune-probe\n' \
    > /tmp/diag.cfg
  "${PHOBOS_HOME}/phobos.sh" --debug --config /tmp/diag.cfg -- /usr/local/libexec/phobos-prune-probe read /etc/hostname 2>&1 \
    | head -40 | sed 's/^/PHOBOS-KVM-DIAG probe: /'
  sleep 2
  dmesg | tail -12 | sed 's/^/PHOBOS-KVM-DIAG ring: /'
}
diagnose

printf 'PHOBOS-KVM-KERNEL %s\n' "$(uname -r)"
python3 /var/tmp/helpers/exercise_pruner/src/interface/main.py --kernel-observer audit --output-dir /var/tmp/path_sets "${KEY}"
status=$?
# What the kernel wrote, for whoever reads the run: the records that replace the fixtures' written ones.
dmesg | grep -E 'type=(1423|1424|LANDLOCK)' > /var/tmp/path_sets/audit-raw.log
finish "${status}"
