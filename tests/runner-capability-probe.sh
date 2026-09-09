#!/usr/bin/env bash
# Answers what a machine can actually do, before Phobos CI asks it to.
#
# Two of the things Phobos wants to test in CI depend on the machine rather
# than on this repository: whether Landlock enforces inside an ordinary
# container, and whether Bubblewrap can build a sandbox at all. Neither can be
# read out of the source, and a runner image can withdraw either without
# warning, so the question is asked here and asked the same way every time.
#
#   runner-capability-probe.sh --report           survey, always exits 0
#   runner-capability-probe.sh --assert-landlock  0 enforced, 1 not, 3 cannot tell
#   runner-capability-probe.sh --assert-bwrap     0 sandboxed, 1 not, 3 cannot tell
#
# The assert modes are three-valued on purpose. "The machine cannot do this"
# and "the probe could not find out" call for different responses, and folding
# the second into the first is how a broken probe comes to look like an answer.
#
# --report never fails on an absent capability; that is what the assert modes
# are for. No mode changes a kernel or AppArmor setting: a probe that relaxed
# the host to make itself pass would answer a question nobody asked.
set -uo pipefail

EXIT_AVAILABLE=0
EXIT_UNAVAILABLE=1
EXIT_INDETERMINATE=3

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROBE_SOURCE="${HERE}/landlock-capability-probe.c"
CONTAINER_IMAGE="${PROBE_CONTAINER_IMAGE:-ubuntu:24.04}"

WORK="$(mktemp -d)" || { printf 'cannot create a working directory\n' >&2; exit 3; }
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

hdr() { printf '\n== %s\n' "$1"; }
ok() { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; }
unknown() { printf '  ????  %s\n' "$1"; }
fact() { printf '  %-34s %s\n' "$1" "$2"; }

# Whatever the command prints, on one line, or a note that it is absent.
value_of() {
    command -v "$1" >/dev/null 2>&1 || { printf 'not installed'; return; }
    local output
    output="$("$@" 2>&1 | head -1)"
    printf '%s' "${output:--}"
}

# One kernel setting, or a note that this kernel does not carry it.
sysctl_value() {
    local value
    value="$(sysctl -n "$1" 2>/dev/null)" || value=""
    printf '%s' "${value:-not present on this kernel}"
}

# Whether an unprivileged user namespace can be created here at all.
userns_verdict() {
    if unshare -Ur true >/dev/null 2>&1; then
        printf 'works'
    else
        printf 'refused'
    fi
}

# The distribution's own name for itself, read rather than sourced.
distribution_name() {
    [[ -r /etc/os-release ]] || { printf 'unknown'; return; }
    grep -m1 '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '"'
}

# Compiles both probes: one to run here, a static one to run in a container.
build_probes() {
    if ! command -v gcc >/dev/null 2>&1; then
        printf 'gcc is not installed\n' >"${WORK}/build.log"
        return 1
    fi
    gcc -O2 -Wall -Wextra -o "${WORK}/probe" "${PROBE_SOURCE}" 2>"${WORK}/build.log" || return 1
    gcc -O2 -Wall -Wextra -static -o "${WORK}/probe-static" "${PROBE_SOURCE}" 2>>"${WORK}/build.log" || return 1
    return 0
}

# The two files every enforcement check needs: one permitted, one forbidden.
build_fixture() {
    mkdir -p "${WORK}/permitted" "${WORK}/forbidden"
    printf 'public\n' >"${WORK}/permitted/data.txt"
    printf 'classified\n' >"${WORK}/forbidden/secret.txt"
}

# What this machine is, in the terms a later reader of the log will want.
report_machine() {
    hdr "Machine"
    fact "ImageOS" "${ImageOS:-not a GitHub runner}"
    fact "ImageVersion" "${ImageVersion:-not a GitHub runner}"
    fact "kernel" "$(value_of uname -r)"
    fact "architecture" "$(value_of uname -m)"
    fact "distribution" "$(distribution_name)"
    fact "effective uid" "${EUID}"
    fact "docker server" "$(value_of docker version --format '{{.Server.Version}}')"
    fact "docker security options" "$(value_of docker info --format '{{join .SecurityOptions \", \"}}')"
}

# Landlock as the kernel advertises it, and as it actually behaves.
report_landlock() {
    hdr "Landlock"
    if [[ -r /sys/kernel/security/lsm ]]; then
        fact "active LSMs" "$(cat /sys/kernel/security/lsm)"
    else
        fact "active LSMs" "unreadable here, which is normal inside a container"
    fi
    if ! build_probes; then
        fact "probe" "cannot be built; see the log below"
        sed 's/^/    /' "${WORK}/build.log"
        return
    fi
    fact "reported ABI" "$(value_of "${WORK}/probe" --version)"
    build_fixture
    "${WORK}/probe" --enforce "${WORK}/permitted" "${WORK}/permitted/data.txt" \
        "${WORK}/forbidden/secret.txt" >"${WORK}/host.log" 2>&1
    fact "enforces on this host" "$(word_for_exit "$?")"
    fact "enforces in a plain container" "$(word_for_exit "$(container_enforcement_status)")"
}

# The three-valued verdict as one word, for a report line.
word_for_exit() {
    case "$1" in
        "${EXIT_AVAILABLE}") printf 'yes' ;;
        "${EXIT_UNAVAILABLE}") printf 'no' ;;
        *) printf 'cannot tell' ;;
    esac
}

# The container probe's own exit status, kept distinct from docker's failures.
#
# Docker reports its own troubles with 125 and upwards, so a status of 1 is the
# probe saying no, and anything else is the probe never having been asked.
container_enforcement_status() {
    if ! command -v docker >/dev/null 2>&1; then
        printf '%s' "${EXIT_INDETERMINATE}"
        return
    fi
    if [[ ! -x "${WORK}/probe-static" ]]; then
        printf '%s' "${EXIT_INDETERMINATE}"
        return
    fi
    run_probe_in_container >"${WORK}/container.log" 2>&1
    local status="$?"
    case "${status}" in
        "${EXIT_AVAILABLE}"|"${EXIT_UNAVAILABLE}") printf '%s' "${status}" ;;
        *) printf '%s' "${EXIT_INDETERMINATE}" ;;
    esac
}

# A plain docker run: no --privileged, no --cap-add, no --security-opt, ever.
run_probe_in_container() {
    docker run --rm \
        -v "${WORK}/probe-static:/probe:ro" \
        -v "${WORK}/permitted:/permitted:ro" \
        -v "${WORK}/forbidden:/forbidden:ro" \
        "${CONTAINER_IMAGE}" \
        /probe --enforce /permitted /permitted/data.txt /forbidden/secret.txt
}

# Bubblewrap, and the AppArmor setting that decides whether it may run at all.
report_bwrap() {
    hdr "Bubblewrap and user namespaces"
    fact "bwrap" "$(value_of bwrap --version)"
    fact "apparmor_restrict_unprivileged_userns" \
        "$(sysctl_value kernel.apparmor_restrict_unprivileged_userns)"
    fact "unprivileged_userns_clone" "$(sysctl_value kernel.unprivileged_userns_clone)"
    if [[ -r /sys/kernel/security/apparmor/profiles ]]; then
        local profiles
        profiles="$(grep -c bwrap /sys/kernel/security/apparmor/profiles 2>/dev/null)"
        fact "loaded AppArmor bwrap profiles" "${profiles:-0}"
    else
        fact "loaded AppArmor bwrap profiles" "the profile list is unreadable here"
    fi
    fact "unshare -Ur" "$(userns_verdict)"
    fact "the pruner's own flag list" "$(pruner_flag_verdict)"
}

# Whether the flags the pruner passes today are flags Bubblewrap knows.
#
# The pruner asks for --unshare-utc, which Bubblewrap has never had; the option
# is --unshare-uts. This reads the help output rather than running a sandbox,
# so a host that forbids namespaces cannot be mistaken for a rejected flag.
pruner_flag_verdict() {
    if ! command -v bwrap >/dev/null 2>&1; then
        printf 'not checked, bwrap is absent'
        return
    fi
    if bwrap --help 2>&1 | grep -q -- '--unshare-utc'; then
        printf 'accepted'
    else
        printf 'rejected: --unshare-utc is not an option, --unshare-uts is'
    fi
}

# Landlock has to enforce here and in an ordinary container, or B3 cannot run.
assert_landlock() {
    hdr "Assert: Landlock enforces"
    if ! build_probes; then
        unknown "the probe could not be built"
        sed 's/^/    /' "${WORK}/build.log"
        return "${EXIT_INDETERMINATE}"
    fi
    build_fixture
    "${WORK}/probe" --enforce "${WORK}/permitted" "${WORK}/permitted/data.txt" \
        "${WORK}/forbidden/secret.txt"
    local host_status="$?"
    case "${host_status}" in
        "${EXIT_AVAILABLE}") ok "Landlock enforces on this host" ;;
        "${EXIT_UNAVAILABLE}") bad "Landlock does not enforce on this host" ;;
        *) unknown "the host probe could not reach a verdict"; return "${EXIT_INDETERMINATE}" ;;
    esac

    if ! command -v docker >/dev/null 2>&1; then
        unknown "docker is absent, so enforcement in a container cannot be shown"
        return "${EXIT_INDETERMINATE}"
    fi
    local container_status
    container_status="$(container_enforcement_status)"
    case "${container_status}" in
        "${EXIT_AVAILABLE}") ok "Landlock enforces inside ${CONTAINER_IMAGE}, started with no security flags" ;;
        "${EXIT_UNAVAILABLE}") bad "Landlock does not enforce inside ${CONTAINER_IMAGE}" ;;
        *) unknown "the container probe could not reach a verdict" ;;
    esac
    [[ -s "${WORK}/container.log" ]] && sed 's/^/    /' "${WORK}/container.log"

    if [[ "${host_status}" == "${EXIT_AVAILABLE}" && "${container_status}" == "${EXIT_AVAILABLE}" ]]; then
        return "${EXIT_AVAILABLE}"
    fi
    if [[ "${container_status}" == "${EXIT_INDETERMINATE}" ]]; then
        return "${EXIT_INDETERMINATE}"
    fi
    return "${EXIT_UNAVAILABLE}"
}

# The directories a sandboxed build needs, read-only, as the pruner binds them.
system_bindings() {
    local directory
    for directory in /bin /usr/bin /lib /lib64 /usr/lib /etc; do
        [[ -e "${directory}" ]] && printf '%s\n%s\n%s\n' "--ro-bind" "${directory}" "${directory}"
    done
    for directory in /lib/*-linux-gnu; do
        [[ -e "${directory}" ]] && printf '%s\n%s\n%s\n' "--ro-bind" "${directory}" "${directory}"
    done
    return 0
}

# Bubblewrap in the shape the pruner uses it, running a real script.
#
# Not bwrap /bin/true: the namespaces, the tmpfs root and the bound work
# directory are the parts that fail on a restricted host, and a trivial
# invocation exercises none of them. The host /tmp is deliberately not bound
# in, unlike the pruner, which needs that fixed rather than reproduced.
assert_bwrap() {
    hdr "Assert: Bubblewrap sandboxes"
    if ! command -v bwrap >/dev/null 2>&1; then
        unknown "bwrap is not installed, so nothing was measured"
        return "${EXIT_INDETERMINATE}"
    fi
    if [[ "${EUID}" -eq 0 ]]; then
        unknown "running as root, which is exempt from the restriction this is meant to measure"
        return "${EXIT_INDETERMINATE}"
    fi
    local sandbox_workdir="/var/tmp/testing-dir"
    mkdir -p "${WORK}/exercise"
    printf '#!/bin/bash\necho sandboxed-build-ran\n' >"${WORK}/exercise/build_script.sh"
    chmod +x "${WORK}/exercise/build_script.sh"

    local options=()
    readarray -t options < <(system_bindings)
    local output
    output="$(bwrap \
        --tmpfs / \
        --tmpfs /tmp \
        "${options[@]}" \
        --dir /var --dir /var/tmp --dir "${sandbox_workdir}" \
        --bind "${WORK}/exercise" "${sandbox_workdir}" \
        --proc /proc --dev /dev --share-net \
        --unshare-pid --unshare-uts --unshare-ipc \
        --chdir "${sandbox_workdir}" \
        -- /bin/bash "${sandbox_workdir}/build_script.sh" 2>&1)"
    local status="$?"
    if [[ "${status}" -eq 0 && "${output}" == *sandboxed-build-ran* ]]; then
        ok "Bubblewrap built a production-shaped sandbox and ran a script inside it"
        return "${EXIT_AVAILABLE}"
    fi
    bad "Bubblewrap could not build a production-shaped sandbox (exit ${status})"
    printf '%s\n' "${output}" | sed 's/^/    /'
    return "${EXIT_UNAVAILABLE}"
}

# One line naming the verdict, so a log reader never has to decode a number.
announce() {
    case "$1" in
        "${EXIT_AVAILABLE}") printf '\nverdict: available\n' ;;
        "${EXIT_UNAVAILABLE}") printf '\nverdict: unavailable on this machine\n' ;;
        *) printf '\nverdict: indeterminate, the probe could not answer\n' ;;
    esac
    exit "$1"
}

usage() {
    sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 2
}

case "${1:-}" in
    --report)
        report_machine
        report_landlock
        report_bwrap
        printf '\nA survey only. Nothing here fails the run; use the assert modes for that.\n'
        ;;
    --assert-landlock)
        assert_landlock
        announce "$?"
        ;;
    --assert-bwrap)
        assert_bwrap
        announce "$?"
        ;;
    *)
        usage
        ;;
esac
