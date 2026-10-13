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
#   build-kvm-kernel.sh --check <directory>
#
# The first form leaves <destination>/bzImage, <destination>/config and <destination>/build.txt, which names
# the kernel version, the SHA-256 of its tarball, the compiler and the runner image it was built with, and
# the SHA-256 of bzImage and config. It needs gcc, make, flex, bison, bc, libelf, libssl and the headers of
# both on the runner (the workflow installs them), and curl and sha256sum.
#
# The second form checks a kernel built by the first, as prune-kvm.yml restores one from its cache: that
# build.txt names this script's version and tarball, that bzImage and config are the files it names, and
# that the configuration passes the same checks a fresh build is held to. That finds a kernel altered by
# accident or built by another version of this script; it is no defence against a cache entry written on
# purpose, which is why only trusted runs write that cache.
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

# Ends with EXIT_UNFIT unless the kernel configuration $1 holds every option the guest needs built in and
# names landlock in the LSM list it starts.
check_configuration() {
  local wanted
  for wanted in CONFIG_SECURITY_LANDLOCK=y CONFIG_AUDIT=y CONFIG_VIRTIO_BLK=y CONFIG_EXT4_FS=y CONFIG_SECCOMP_FILTER=y \
                CONFIG_SECURITY_NETWORK=y CONFIG_VIRTIO_PCI=y CONFIG_SERIAL_8250_CONSOLE=y CONFIG_MAGIC_SYSRQ=y CONFIG_ACPI=y; do
    if ! grep -q "^${wanted}$" "$1"; then
      printf 'the configuration lacks %s\n' "${wanted}" >&2
      exit "${EXIT_UNFIT}"
    fi
  done
  if ! grep -q '^CONFIG_LSM=".*landlock.*"$' "$1"; then
    printf 'landlock is not in the LSM list of the configuration\n' >&2
    exit "${EXIT_UNFIT}"
  fi
}

# Prints the value of the line key=value named $2 in the file $1, or nothing.
build_value() {
  sed -n "s/^$2=//p" "$1" | head -n 1
}

# Ends with EXIT_UNFIT unless the directory $1 holds a kernel this script built, unaltered, whose
# configuration passes check_configuration.
check_built() {
  local name
  [[ -f "$1/bzImage" && -f "$1/config" && -f "$1/build.txt" ]] \
    || { printf '%s does not hold bzImage, config and build.txt\n' "$1" >&2; exit "${EXIT_UNFIT}"; }
  [[ "$(build_value "$1/build.txt" kernel_version)" == "${KERNEL_VERSION}" \
     && "$(build_value "$1/build.txt" tarball_sha256)" == "${KERNEL_SHA256}" ]] \
    || { printf '%s holds a kernel other than Linux %s\n' "$1" "${KERNEL_VERSION}" >&2; exit "${EXIT_UNFIT}"; }
  for name in bzImage config; do
    [[ "$(sha256sum "$1/${name}" | cut -d ' ' -f 1)" == "$(build_value "$1/build.txt" "${name}_sha256")" ]] \
      || { printf '%s/%s is not the file build.txt names\n' "$1" "${name}" >&2; exit "${EXIT_UNFIT}"; }
  done
  check_configuration "$1/config"
  printf 'Checked Linux %s in %s, built with %s on %s %s\n' "${KERNEL_VERSION}" "$1" \
    "$(build_value "$1/build.txt" compiler)" "$(build_value "$1/build.txt" image_os)" "$(build_value "$1/build.txt" image_version)"
}

if [[ $# -eq 2 && "$1" == "--check" ]]; then
  check_built "$2"
  exit 0
fi
[[ $# -eq 1 && "$1" != --* ]] || { printf 'usage: build-kvm-kernel.sh <destination directory> | --check <directory>\n' >&2; exit "${EXIT_USAGE}"; }
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
check_configuration .config

make -j"$(nproc)" bzImage
cp arch/x86/boot/bzImage "${DESTINATION}/bzImage"
cp .config "${DESTINATION}/config"
{
  printf 'kernel_version=%s\n' "${KERNEL_VERSION}"
  printf 'tarball_sha256=%s\n' "${KERNEL_SHA256}"
  printf 'compiler=%s\n' "$(gcc --version | head -n 1)"
  printf 'image_os=%s\n' "${ImageOS:-unknown}"
  printf 'image_version=%s\n' "${ImageVersion:-unknown}"
  printf 'bzImage_sha256=%s\n' "$(sha256sum "${DESTINATION}/bzImage" | cut -d ' ' -f 1)"
  printf 'config_sha256=%s\n' "$(sha256sum "${DESTINATION}/config" | cut -d ' ' -f 1)"
} > "${DESTINATION}/build.txt"
check_built "${DESTINATION}"
printf 'Built Linux %s (sha256 of the tarball %s) into %s\n' "${KERNEL_VERSION}" "${KERNEL_SHA256}" "${DESTINATION}"
