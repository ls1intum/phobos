#!/usr/bin/env bash
# Installs, checks and runs the one toolchain libnetblocker.so is built with.
#
# The library is not committed: it is built from source inside the run-phase image, once per
# architecture. Reproducibility still needs one compiler, one linker and one C library,
# installed the same way everywhere, so the versions live here and nowhere else: the
# Dockerfile and this script are the single source of the toolchain.
#
# On amd64 the packages come from a fixed Ubuntu snapshot rather than the moving archive, so an
# update to gcc-14 does not change the bytes behind anyone's back; Ubuntu keeps a snapshot for
# at least two years, and moving it is a deliberate change. On other architectures the snapshot
# has no packages, so the toolchain comes from the ordinary archive and the build is functional
# but not byte-reproducible.
#
#   netblocker-build.sh install [PACKAGE...]      as root, on Ubuntu 26.04
#   netblocker-build.sh build SOURCE_DIRECTORY OUTPUT
#   netblocker-build.sh verify LIBRARY
#   netblocker-build.sh compare REFERENCE COPY...
set -euo pipefail

# The status this script ends with when it was called the wrong way.
readonly EXIT_USAGE=2
readonly SNAPSHOT="20260912T000000Z"
readonly GCC_VERSION="14.3.0-14ubuntu1"
readonly BINUTILS_VERSION="2.46-3ubuntu2"
readonly LIBC_DEV_VERSION="2.43-2ubuntu2.4"
# The C library of the run-phase image. A library needing a newer one would not load there.
readonly HIGHEST_GLIBC="2.39"
# The ELF machines Phobos supports, as readelf's --wide file header prints them, the two
# architectures the images are built for. No library is committed: it is built inside each
# architecture's image and verified there, so verify accepts either rather
# than holding every build to x86-64.
readonly SUPPORTED_MACHINES="Advanced Micro Devices X86-64|AArch64"
# The only functions the library may export: its six hooks, in the order the C locale sorts them.
readonly EXPORTED_FUNCTIONS="bind connect getaddrinfo sendmmsg sendmsg sendto"

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Prints how to call this script and gives up.
usage() {
    printf 'usage: netblocker-build.sh install [PACKAGE...]\n' >&2
    printf '       netblocker-build.sh build SOURCE_DIRECTORY OUTPUT\n' >&2
    printf '       netblocker-build.sh verify LIBRARY\n' >&2
    printf '       netblocker-build.sh compare REFERENCE COPY...\n' >&2
    exit "${EXIT_USAGE}"
}

# Reports why the script stops and stops.
fail() {
    printf 'netblocker-build.sh: %s\n' "$1" >&2
    exit 1
}

# Answers whether this machine is the architecture the committed objects are built
# for. Only there is the toolchain pinned: the snapshot service covers the archive
# amd64 installs from and not the ports archive other architectures use, and only the
# amd64 build is compared byte for byte. Assumes dpkg.
pinned_architecture() {
    [[ "$(dpkg --print-architecture)" == "amd64" ]]
}

# Installs the toolchain and any further packages, pinned where the architecture
# allows it. Assumes root on Ubuntu 26.04 with the stock archive sources.
install_toolchain() {
    export DEBIAN_FRONTEND=noninteractive
    if pinned_architecture; then
        install_pinned_toolchain "$@"
    else
        install_archive_toolchain "$@"
    fi
    rm -rf /var/lib/apt/lists/*
}

# Installs the pinned toolchain and the further packages from the snapshot.
#
# ca-certificates comes first, from the ordinary archive, because the snapshot is
# served over HTTPS. The archive's package lists are then removed, and a snapshot
# update that fails is an error: apt otherwise prints a warning and quietly installs
# from whatever lists it still has, which would make the pin look effective when it
# is not.
install_pinned_toolchain() {
    apt-get update -qq
    apt-get install --yes --no-install-recommends ca-certificates
    rm -rf /var/lib/apt/lists/*
    apt-get update -qq --snapshot "${SNAPSHOT}" -o APT::Update::Error-Mode=any
    apt-get install --yes --no-install-recommends --snapshot "${SNAPSHOT}" \
        "gcc-14=${GCC_VERSION}" \
        "binutils=${BINUTILS_VERSION}" \
        "libc6-dev=${LIBC_DEV_VERSION}" \
        "$@"
    check_toolchain
}

# Installs the same packages from the ordinary archive, at whatever version it holds,
# and says so. A build made this way is never compared with the committed objects.
install_archive_toolchain() {
    printf 'netblocker-build.sh: %s has no snapshot; installing the toolchain unpinned, so this build is not comparable with the committed amd64 objects\n' \
        "$(dpkg --print-architecture)" >&2
    apt-get update -qq
    apt-get install --yes --no-install-recommends gcc-14 binutils libc6-dev "$@"
}

# Refuses to go on unless the installed toolchain is exactly the pinned one, on the
# architecture that pins it. Assumes a Debian-style system with dpkg-query.
check_toolchain() {
    local pin
    local package
    local installed
    pinned_architecture || return 0
    for pin in "gcc-14=${GCC_VERSION}" "binutils=${BINUTILS_VERSION}" "libc6-dev=${LIBC_DEV_VERSION}"; do
        package="${pin%%=*}"
        installed="$(dpkg-query --show --showformat="\${Version}" "${package}" 2>/dev/null || true)"
        [[ "${installed}" == "${pin#*=}" ]] \
            || fail "${package} is ${installed:-not installed}, but the pinned version is ${pin#*=}"
    done
}

# Compiles every netblocker*.c in SOURCE_DIRECTORY into OUTPUT with the flags the
# run-phase image has always used, plus -fvisibility=hidden.
#
# -O2 is what switches _FORTIFY_SOURCE on: without an optimisation level it is off, and
# this library sits on every connection a submission makes. -Wl,-z,now makes every
# relocation resolve at load time. -fvisibility=hidden keeps every function but the six
# hooks, which ask for default visibility themselves, out of the dynamic symbol table.
# The sources are compiled from their own directory under their bare names, in the
# order the C locale sorts them, so the bytes depend neither on where the checkout lives
# nor on the machine's locale.
build_library() {
    local directory="$1"
    local output
    local -a sources
    check_toolchain
    output="$(realpath --canonicalize-missing -- "$2")"
    mapfile -t sources < <(cd -- "${directory}" && LC_ALL=C compgen -G 'netblocker*.c' | LC_ALL=C sort)
    (( ${#sources[@]} > 0 )) || fail "${directory} holds no netblocker*.c"
    (
        cd -- "${directory}"
        gcc-14 -std=gnu23 -O2 -Wall -Wextra -fPIC -shared -fvisibility=hidden -Wl,-z,now \
            -o "${output}" "${sources[@]}"
    )
}

# Refuses a library built for neither architecture Phobos supports, that needs a newer C
# library than the run-phase image has, exports any function but its six hooks, or that
# the network layer would refuse at run time. Assumes readelf and the repository checkout
# this script lives in.
verify_library() {
    local library="$1"
    local machine
    local highest
    local exported
    # shellcheck source=../../core/phobos-common.sh
    source "${HERE}/../../core/phobos-common.sh"
    machine="$(readelf --file-header --wide "${library}" | awk -F':[[:space:]]+' '$1 ~ /Machine$/ { print $2 }')"
    [[ "${machine}" =~ ^(${SUPPORTED_MACHINES})$ ]] || fail "${library} is built for '${machine}', which is neither x86-64 nor AArch64"
    highest="$(readelf --dyn-syms --wide "${library}" | { grep -o 'GLIBC_[0-9.]*' || true; } | sort -uV | tail -n 1)"
    [[ -n "${highest}" ]] || fail "${library} names no glibc symbol version, so it is not the dynamically linked library this job builds"
    highest="${highest#GLIBC_}"
    [[ "$(printf '%s\n%s\n' "${highest}" "${HIGHEST_GLIBC}" | sort -V | tail -n 1)" == "${HIGHEST_GLIBC}" ]] \
        || fail "${library} needs glibc ${highest}, newer than the ${HIGHEST_GLIBC} the run-phase image ships"
    exported="$(defined_library_functions "${library}" | LC_ALL=C sort | paste -s -d ' ' -)"
    [[ "${exported}" == "${EXPORTED_FUNCTIONS}" ]] \
        || fail "${library} exports '${exported}' rather than exactly '${EXPORTED_FUNCTIONS}', so one of its functions could take the place of a program's own"
    refuse_unusable_netblocker "$(realpath -- "${library}")"
}

# Refuses every copy whose bytes differ from the reference. Assumes sha256sum.
compare_copies() {
    local reference="$1"
    shift
    local wanted
    local copy
    local actual
    wanted="$(sha256sum < "${reference}" | cut -d ' ' -f 1)"
    for copy in "$@"; do
        actual="$(sha256sum < "${copy}" | cut -d ' ' -f 1)"
        [[ "${actual}" == "${wanted}" ]] \
            || fail "${copy} is ${actual}, but ${reference} is ${wanted}"
    done
    printf 'identical: %s %s\n' "${wanted}" "$*"
}

[[ $# -ge 1 ]] || usage
case "$1" in
    install)
        shift
        install_toolchain "$@"
        ;;
    build)
        [[ $# -eq 3 ]] || usage
        build_library "$2" "$3"
        ;;
    verify)
        [[ $# -eq 2 ]] || usage
        verify_library "$2"
        ;;
    compare)
        [[ $# -ge 3 ]] || usage
        shift
        compare_copies "$@"
        ;;
    *)
        usage
        ;;
esac
