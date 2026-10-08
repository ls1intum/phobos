#!/usr/bin/env bash
# Builds the guest kernel of the KVM run: Linux 7.2, pinned by version and SHA-256, x86_64 only.
#
# The prune plan's A.6.9 needs a kernel that offers Landlock version 10 and writes Landlock's audit
# records, and the runners' own kernels offer neither (6.17 and 7.0). Booting is not enough, so the
# configuration is made and then checked: Landlock and audit must be compiled in, and Landlock must be in
# the LSM list the kernel starts. The guest proves the rest itself before it prunes anything
# (main.py --kernel-observer audit, kvm.selftest). Everything is built in, no module is needed, which is
# why the guest needs no initial RAM disk.
#
#   build-kvm-kernel.sh <destination directory>
#
# It leaves <destination>/bzImage and <destination>/config. Needs gcc, make, flex, bison, bc, libelf,
# libssl and the headers of both on the runner (the workflow installs them), and curl and sha256sum.
set -euo pipefail

# The kernel to build and the SHA-256 of its tarball, from kernel.org's signed sha256sums.asc. Moving
# the version means moving both, in one commit.
readonly KERNEL_VERSION="7.2.9"
readonly KERNEL_SHA256="b4c5dfbe51a364a6c7f03869200f88c8e1f77403539005f14b7fc6bc91b8d8ba"
readonly KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-${KERNEL_VERSION}.tar.xz"
# The status this script ends with when it was called the wrong way, and when the result is not the
# kernel the run needs.
readonly EXIT_USAGE=2
readonly EXIT_UNFIT=3

[[ $# -eq 1 ]] || { printf 'usage: build-kvm-kernel.sh <destination directory>\n' >&2; exit "${EXIT_USAGE}"; }
mkdir -p "$1"
DESTINATION="$(realpath "$1")"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

curl --fail --silent --show-error --location --retry 3 --output "${WORK}/linux.tar.xz" "${KERNEL_URL}"
printf '%s  %s\n' "${KERNEL_SHA256}" "${WORK}/linux.tar.xz" | sha256sum --check --strict
tar -xJf "${WORK}/linux.tar.xz" -C "${WORK}"
cd "${WORK}/linux-${KERNEL_VERSION}"

make x86_64_defconfig kvm_guest.config
# Landlock and audit are what the run is for; the rest is what a guest that boots from a virtio disk
# on a serial console, runs ptrace, seccomp user notification and a loopback network, needs built in.
for option in SECURITY SECURITY_LANDLOCK AUDIT AUDITSYSCALL EXT4_FS VIRTIO_BLK DEVTMPFS DEVTMPFS_MOUNT PROC_FS SYSFS \
              TMPFS SECCOMP SECCOMP_FILTER PTRACE INET IPV6 UNIX BINFMT_ELF BINFMT_SCRIPT SERIAL_8250 \
              SERIAL_8250_CONSOLE MAGIC_SYSRQ POSIX_TIMERS FHANDLE SECURITY_NETWORK VIRTIO_PCI ACPI BLK_DEV; do
  scripts/config --enable "${option}"
done
scripts/config --enable DEBUG_INFO_NONE --disable DEBUG_INFO_BTF
scripts/config --set-str LSM "landlock,lockdown,yama,integrity"
make olddefconfig

for wanted in CONFIG_SECURITY_LANDLOCK=y CONFIG_AUDIT=y CONFIG_VIRTIO_BLK=y CONFIG_EXT4_FS=y CONFIG_SECCOMP_FILTER=y \
              CONFIG_SECURITY_NETWORK=y CONFIG_VIRTIO_PCI=y CONFIG_SERIAL_8250_CONSOLE=y CONFIG_MAGIC_SYSRQ=y CONFIG_ACPI=y; do
  if ! grep -q "^${wanted}$" .config; then
    printf 'the configuration lacks %s\n' "${wanted}" >&2
    exit "${EXIT_UNFIT}"
  fi
done
if ! grep -q '^CONFIG_LSM=".*landlock.*"$' .config; then
  printf 'landlock is not in the LSM list of the configuration\n' >&2
  exit "${EXIT_UNFIT}"
fi

make -j"$(nproc)" bzImage
cp arch/x86/boot/bzImage "${DESTINATION}/bzImage"
cp .config "${DESTINATION}/config"
printf 'Built Linux %s (sha256 of the tarball %s) into %s\n' "${KERNEL_VERSION}" "${KERNEL_SHA256}" "${DESTINATION}"
