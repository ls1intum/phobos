#!/usr/bin/env bash
# Answers what a machine can actually do, before Phobos CI asks it to.
#
# Some of the things Phobos wants to test in CI depend on the machine rather
# than on this repository: whether Landlock enforces inside an ordinary
# container, whether Bubblewrap can build a sandbox at all, and whether ptrace
# sees a traced Landlock refusal. None can be read out of the source, and a runner
# image can withdraw any without warning, so each question is asked here, the same way.
#
#   runner-capability-probe.sh --report           survey, always exits 0
#   runner-capability-probe.sh --assert-landlock  0 enforced, 1 not, 3 cannot tell
#   runner-capability-probe.sh --assert-bwrap     0 sandboxed, 1 not, 3 cannot tell
#   runner-capability-probe.sh --assert-kvm       0 a guest kernel boots under KVM, 1 not, 3 cannot tell
#   runner-capability-probe.sh --assert-ptrace    0 a traced Landlock denial is seen, 1 not, 3 cannot tell
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
PROBE_SOURCE="${HERE}/landlock-filesystem-and-networksystem-capability-probe.c"
PTRACE_PROBE_SOURCE="${HERE}/ptrace-observer-capability-probe.c"
# The uid and gid the ptrace probe runs as inside its container: nobody, which holds no capability.
UNPRIVILEGED_UID=65534
CONTAINER_IMAGE="${PROBE_CONTAINER_IMAGE:-ubuntu:26.04}"
# How long a guest kernel may take to boot to its end, in seconds, with the host's virtualisation and without.
KVM_BOOT_SECONDS=90
SOFTWARE_BOOT_SECONDS=240
# The memory the guest gets, in megabytes. It never reaches user space, so it needs little.
GUEST_MEMORY_MB=512

WORK="$(mktemp -d)" || { printf 'cannot create a working directory\n' >&2; exit "${EXIT_INDETERMINATE}"; }
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

# The flags the pruner passes today, and whether this Bubblewrap knows them all.
#
# Read from the help output rather than by running a sandbox, so that a host which
# forbids namespaces cannot be mistaken for a rejected flag. The list is the one
# var/tmp/pruning/detect_minimal_fs.sh builds its invocation from; a flag added there
# and not here is only missing from this report, not from the prune.
PRUNER_FLAGS="--tmpfs --clearenv --ro-bind --bind --dir --setenv --proc --dev --share-net --new-session --unshare-pid --unshare-uts --unshare-ipc --chdir"

pruner_flag_verdict() {
  if ! command -v bwrap >/dev/null 2>&1; then
    printf 'not checked, bwrap is absent'
    return
  fi
  local help
  local flag
  local unknown=""
  help="$(bwrap --help 2>&1)"
  for flag in ${PRUNER_FLAGS}; do
    grep -q -- "${flag}" <<<"${help}" || unknown+="${flag} "
  done
  if [[ -z "${unknown}" ]]; then
    printf 'all accepted'
  else
    printf 'rejected: %s' "${unknown% }"
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

# The QEMU binary, machine type and serial console for this host's architecture, one per line, or nothing
# where this probe does not know the architecture.
guest_description() {
  case "$(uname -m)" in
    x86_64) printf '%s\n' qemu-system-x86_64 q35 ttyS0 ;;
    aarch64) printf '%s\n' qemu-system-aarch64 virt ttyAMA0 ;;
    *) return 1 ;;
  esac
}

# The kernel image this host booted, readable by this user, copied into the working directory when it is not,
# or nothing where it cannot be had. Ubuntu keeps /boot/vmlinuz-* unreadable to an ordinary user.
host_kernel_image() {
  local image
  image="/boot/vmlinuz-$(uname -r)"
  [[ -e "${image}" ]] || return 1
  if [[ -r "${image}" ]]; then
    printf '%s' "${image}"
    return 0
  fi
  sudo -n cp "${image}" "${WORK}/vmlinuz" 2>/dev/null || return 1
  sudo -n chmod a+r "${WORK}/vmlinuz" 2>/dev/null || return 1
  printf '%s' "${WORK}/vmlinuz"
}

# Whether this user can open /dev/kvm, as a word for a report line.
kvm_access_word() {
  if [[ ! -e /dev/kvm ]]; then
    printf 'there is no /dev/kvm'
  elif [[ -r /dev/kvm && -w /dev/kvm ]]; then
    printf 'yes, without sudo'
  elif sudo -n true 2>/dev/null; then
    printf 'only through sudo'
  else
    printf 'no'
  fi
}

# Boots the host's own kernel under QEMU with the accelerator named by $1, kvm or tcg, for at most $2 seconds,
# with the guest's serial console in ${WORK}/guest-$1.log. The kernel has no root file system to mount, so a
# kernel that came up ends in a panic, which is how it is known to have run, and QEMU then exits because of
# -no-reboot. Prints the seconds it took. Assumes guest_description and host_kernel_image have answered.
boot_guest() {
  local accelerator="$1"
  local limit="$2"
  local -a description=()
  local kernel
  local runner=""
  local started="${SECONDS}"
  readarray -t description < <(guest_description)
  kernel="$(host_kernel_image)" || return 1
  if [[ "${accelerator}" == "kvm" && ! ( -r /dev/kvm && -w /dev/kvm ) ]]; then
    runner="sudo -n"
  fi
  # The runner prefix is a command word on purpose, so it is left to split.
  # shellcheck disable=SC2086
  timeout "${limit}" ${runner} "${description[0]}" -machine "${description[1]},accel=${accelerator}" -cpu "$([[ "${accelerator}" == kvm ]] && printf host || printf max)" \
    -m "${GUEST_MEMORY_MB}" -nographic -no-reboot -kernel "${kernel}" \
    -append "console=${description[2]} panic=-1" >"${WORK}/guest-${accelerator}.log" 2>&1
  printf '%s' "$(( SECONDS - started ))"
}

# Whether the last guest log shows a kernel that came up and then stopped for want of a root: the verdict word
# yes, or no, with the first lines of the log on standard output when it is no.
guest_came_up() {
  local log="${WORK}/guest-$1.log"
  if grep -q 'Linux version' "${log}" 2>/dev/null && grep -q 'Kernel panic' "${log}" 2>/dev/null; then
    printf 'yes'
  else
    printf 'no'
  fi
}

# The virtualisation as the machine offers it and as QEMU can use it, with the software fallback timed beside it.
report_kvm() {
  hdr "Virtualisation"
  fact "/dev/kvm" "$([[ -e /dev/kvm ]] && ls -l /dev/kvm | awk '{print $1, $3, $4}' || printf 'absent')"
  fact "opened by this user" "$(kvm_access_word)"
  if [[ "$(uname -m)" == "x86_64" ]]; then
    fact "cpu virtualisation flag" "$(grep -m1 -o -w -E 'vmx|svm' /proc/cpuinfo || printf 'none listed')"
  fi
  fact "qemu" "$(value_of "$(guest_description | head -1)" --version)"
  if ! guest_description >/dev/null || ! command -v "$(guest_description | head -1)" >/dev/null 2>&1; then
    fact "boot test" "not run: no qemu for this architecture"
    return
  fi
  if ! host_kernel_image >/dev/null; then
    fact "boot test" "not run: the host's kernel image cannot be read"
    return
  fi
  if [[ -e /dev/kvm ]]; then
    local seconds
    seconds="$(boot_guest kvm "${KVM_BOOT_SECONDS}")"
    fact "guest under KVM came up" "$(guest_came_up kvm), after ${seconds} s"
  fi
  local software
  software="$(boot_guest tcg "${SOFTWARE_BOOT_SECONDS}")"
  fact "guest in software came up" "$(guest_came_up tcg), after ${software} s"
}

# A guest kernel has to boot under KVM, or a newer kernel than the runner's cannot be tried in a virtual machine.
assert_kvm() {
  hdr "Assert: a virtual machine boots under KVM"
  if ! guest_description >/dev/null; then
    unknown "this probe knows no QEMU for $(uname -m)"
    return "${EXIT_INDETERMINATE}"
  fi
  local binary
  binary="$(guest_description | head -1)"
  if ! command -v "${binary}" >/dev/null 2>&1; then
    unknown "${binary} is not installed, so nothing was measured"
    return "${EXIT_INDETERMINATE}"
  fi
  if [[ ! -e /dev/kvm ]]; then
    bad "there is no /dev/kvm on this machine"
    return "${EXIT_UNAVAILABLE}"
  fi
  if ! host_kernel_image >/dev/null; then
    unknown "the host's kernel image cannot be read, so there is nothing to boot"
    return "${EXIT_INDETERMINATE}"
  fi
  local seconds
  seconds="$(boot_guest kvm "${KVM_BOOT_SECONDS}")"
  if [[ "$(guest_came_up kvm)" == "yes" ]]; then
    ok "a guest kernel booted under KVM in ${seconds} s (access: $(kvm_access_word))"
    return "${EXIT_AVAILABLE}"
  fi
  if grep -q -i -E 'could not access KVM|failed to initialize kvm|Permission denied' "${WORK}/guest-kvm.log"; then
    bad "QEMU could not use KVM"
    sed 's/^/    /' "${WORK}/guest-kvm.log" | head -10
    return "${EXIT_UNAVAILABLE}"
  fi
  unknown "the guest did not come up in ${KVM_BOOT_SECONDS} s and QEMU gave no reason"
  sed 's/^/    /' "${WORK}/guest-kvm.log" | tail -15
  return "${EXIT_INDETERMINATE}"
}

# Compiles the ptrace probe statically, so that it runs in a container image without a compiler.
build_ptrace_probe() {
  if ! command -v gcc >/dev/null 2>&1; then
    printf 'gcc is not installed\n' >"${WORK}/ptrace-build.log"
    return 1
  fi
  gcc -O2 -Wall -Wextra -static -o "${WORK}/ptrace-probe" "${PTRACE_PROBE_SOURCE}" 2>"${WORK}/ptrace-build.log"
}

# The ptrace probe in a plain docker run, as the prune container is started: --network none and
# nothing else, no --privileged, no --cap-add, no --security-opt. It runs as an ordinary uid
# rather than the container's root, so the answer holds for a tracer with no privilege at all.
# Its one line goes to standard output and its reasons to ${WORK}/ptrace-container.log.
run_ptrace_probe_in_container() {
  docker run --rm --network none --user "${UNPRIVILEGED_UID}:${UNPRIVILEGED_UID}" \
    -v "${WORK}/ptrace-probe:/probe:ro" \
    "${CONTAINER_IMAGE}" \
    /probe 2>"${WORK}/ptrace-container.log"
}

# The three-valued verdict for one line of the ptrace probe. Only the line decides, never the
# status, because docker's own failures end with statuses of their own.
ptrace_status_for_line() {
  case "$1" in
    "OBSERVED "*) printf '%s' "${EXIT_AVAILABLE}" ;;
    "TRACEME-REFUSED "*|"NOT-OBSERVED") printf '%s' "${EXIT_UNAVAILABLE}" ;;
    *) printf '%s' "${EXIT_INDETERMINATE}" ;;
  esac
}

# The ptrace probe's line from a plain container, or a note saying why there is none. Assumes
# build_ptrace_probe has run.
ptrace_line_in_container() {
  if ! command -v docker >/dev/null 2>&1; then
    printf 'docker is absent'
    return
  fi
  if [[ ! -x "${WORK}/ptrace-probe" ]]; then
    printf 'the probe could not be built'
    return
  fi
  local line
  line="$(run_ptrace_probe_in_container | head -1)"
  printf '%s' "${line:-no line, the container did not run the probe}"
}

# Whether the layer pruner's observer can work here: ptrace as the kernel restricts it, and the
# probe's answer on this host and inside a plain container.
report_ptrace() {
  hdr "ptrace"
  local scope="absent"
  [[ -r /proc/sys/kernel/yama/ptrace_scope ]] && scope="$(cat /proc/sys/kernel/yama/ptrace_scope)"
  fact "yama ptrace_scope" "${scope}"
  if ! build_ptrace_probe; then
    fact "probe" "cannot be built; see the log below"
    sed 's/^/    /' "${WORK}/ptrace-build.log"
    return
  fi
  fact "observes a denial on this host" "$("${WORK}/ptrace-probe" 2>/dev/null | head -1)"
  fact "observes a denial in a container" "$(ptrace_line_in_container)"
}

# A tracer without privileges has to see a traced process's Landlock refusal inside an ordinary
# container, or the layer pruner has no observer.
assert_ptrace() {
  hdr "Assert: ptrace observes a Landlock denial"
  if ! build_ptrace_probe; then
    unknown "the probe could not be built"
    sed 's/^/    /' "${WORK}/ptrace-build.log"
    return "${EXIT_INDETERMINATE}"
  fi
  local line
  line="$(ptrace_line_in_container)"
  local status
  status="$(ptrace_status_for_line "${line}")"
  case "${status}" in
    "${EXIT_AVAILABLE}") ok "a traced child's Landlock refusal was seen inside ${CONTAINER_IMAGE}: ${line}" ;;
    "${EXIT_UNAVAILABLE}") bad "a traced child's Landlock refusal was not seen inside ${CONTAINER_IMAGE}: ${line}" ;;
    *) unknown "the probe could not reach a verdict inside ${CONTAINER_IMAGE}: ${line}" ;;
  esac
  [[ -s "${WORK}/ptrace-container.log" ]] && sed 's/^/    /' "${WORK}/ptrace-container.log"
  return "${status}"
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

# The lines of this file's header comment that are its usage text, and the status a call made
# the wrong way ends with.
USAGE_FIRST_LINE=2
USAGE_LAST_LINE=22
EXIT_USAGE=2

usage() {
  sed -n "${USAGE_FIRST_LINE},${USAGE_LAST_LINE}p" "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${EXIT_USAGE}"
}

case "${1:-}" in
  --report)
    report_machine
    report_landlock
    report_bwrap
    report_kvm
    report_ptrace
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
  --assert-kvm)
    assert_kvm
    announce "$?"
    ;;
  --assert-ptrace)
    assert_ptrace
    announce "$?"
    ;;
  *)
    usage
    ;;
esac
