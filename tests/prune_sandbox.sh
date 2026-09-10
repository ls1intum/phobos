#!/usr/bin/env bash
# Runs the pruner for real, against a fixture tree rather than the machine.
#
# Everything else that tests the prune phase replaces the pruner with a stub, so
# nothing exercised the part that actually matters: the sandbox it builds, what it
# concludes about a directory, and what it hands to the kernel while doing so.
#
# The fixture is what makes this safe to run on a pull request. A production prune
# asks what the whole filesystem is needed for, which on a shared machine means
# binding its system directories writable to find out. Here the question is asked of
# a tree this script made, and everything the run writes, logs included, stays inside
# it, so two runs at once cannot read or delete each other's evidence.
#
#   tests/prune_sandbox.sh
#
# Bubblewrap needs an unprivileged user namespace. Where the host refuses one the
# checks that need it are skipped, unless PHOBOS_REQUIRE_BWRAP is set, which turns that
# skip into a failure. Anything that would otherwise read a skip as a pass should set it.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PRODUCER="${HERE}/../var/tmp/pruning/run_minimal_fs_all.sh"
PRUNER="${HERE}/../var/tmp/pruning/detect_minimal_fs.sh"

passed=0
failed=0
skipped=0

ok() { printf 'ok    %s\n' "$1"; passed=$((passed + 1)); }
bad() { printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"; failed=$((failed + 1)); }
skip() { printf 'SKIP  %s\n        reason:   %s\n' "$1" "$2"; skipped=$((skipped + 1)); }

summary() {
    echo
    printf '%d passed, %d failed, %d skipped\n' "${passed}" "${failed}" "${skipped}"
    if (( skipped > 0 )); then
        printf 'Skipped checks did not run and are not counted as passing.\n'
    fi
    (( failed == 0 )) || exit 1
    exit 0
}

# Whether this machine will let bubblewrap build a sandbox at all.
#
# The whole filesystem read-only, so that a failure here is the namespace being
# refused and not a missing loader: under a tmpfs root a dynamically linked binary
# fails at execvp, which looks the same from outside and means something else.
bwrap_works() {
    command -v bwrap >/dev/null 2>&1 || return 1
    bwrap --ro-bind / / --unshare-pid -- /bin/true >/dev/null 2>&1
}

# The name that would be a command if anything still passed it through a shell. It
# holds no slash, so mkdir makes one directory rather than a hierarchy, and the marker
# it would create is relative, so it lands wherever that shell happened to be.
AWKWARD_NAME='awkward $(touch INJECTED) ;semicolon '"'"'single'"'"' "double"'

# A tree to prune, an exercise whose build script needs one part of it, and a sibling
# just outside the target that nothing in the run may reach.
build_fixture() {
    local root="$1"
    mkdir -p "${root}/target/needed" "${root}/target/unneeded" "${root}/helpers"
    mkdir -p "${root}/logs" "${root}/scratch" "${root}/out"
    mkdir -p "${root}/testing-dir/java/exercise1/assignment"
    mkdir -p "${root}/target/${AWKWARD_NAME}"
    # Same prefix as the target, one level up. A prune that matched the target's name
    # rather than descending into it would take this with it.
    mkdir -p "${root}/target-secret/private"
    printf 'the build reads this\n' >"${root}/target/needed/input.txt"
    printf 'nothing reads this\n' >"${root}/target/unneeded/spare.txt"
    printf 'not for the sandbox\n' >"${root}/target-secret/private/secret.txt"

    write_build_script "${root}" ''
    cat >"${root}/helpers/emit_artifacts.py" <<'STUB'
import os
import sys

arguments = dict(zip(sys.argv[1:-1:2], sys.argv[2::2]))
destination = os.path.join(
    arguments["--out-dir"],
    "{}_{}.paths".format(arguments["--lang"], arguments["--exercise"]),
)
with open(arguments["--config-file"], encoding="utf-8") as source:
    lines = [line for line in source if " -> " in line]
with open(destination, "w", encoding="utf-8") as handle:
    for line in lines:
        path, mode = line.rsplit(" -> ", 1)
        handle.write("{} {}\n".format(mode.strip(), path.strip()))
STUB
    chmod +x "${root}/helpers/emit_artifacts.py"
}

# The exercise's build script: reads the one directory it needs, plus whatever line a
# particular check wants to put in front of that.
write_build_script() {
    local root="$1" extra="$2"
    cat >"${root}/testing-dir/java/exercise1/build_script.sh" <<STUB
#!/usr/bin/env bash
set -eu
${extra}
cat "${root}/target/needed/input.txt" > /dev/null
echo "build-ran"
STUB
    chmod +x "${root}/testing-dir/java/exercise1/build_script.sh"
}

# A bwrap on PATH that records its argument vector, NUL-delimited, and then runs the
# real one. Reading that file is how a check sees what reached the kernel, rather than
# what a diagnostic said about it afterwards.
install_bwrap_recorder() {
    local root="$1" real
    real="$(command -v bwrap)"
    mkdir -p "${root}/bin"
    cat >"${root}/bin/bwrap" <<STUB
#!/usr/bin/env bash
printf '%s\\0' "\$@" >> "${root}/logs/argv"
exec "${real}" "\$@"
STUB
    chmod +x "${root}/bin/bwrap"
}

run_prune() {
    local root="$1"
    PATH="${root}/bin:${PATH}" \
        TESTING_DIR="${root}/testing-dir" \
        PRUNE_SCRIPT="${PRUNER}" \
        OUTPUT_DIR="${root}/out" \
        HELPER_DIR="${root}/helpers" \
        PRUNE_TARGET="${root}/target" \
        PRUNE_LOG_DIR="${root}/logs" \
        TMPDIR="${root}/scratch" \
        bash "${PRODUCER}" java
}

# Whether the sandboxed build reached its last line. Every check that concludes from
# the absence of something has to establish this first, or a run that never happened
# would satisfy it.
the_build_ran() {
    grep -qs "build-ran" "$1"/logs/build-*.log
}

# Whether one exact string is one whole argument in the recorded vector.
argv_holds() {
    PHOBOS_ARGV_FILE="$1" PHOBOS_WANTED="$2" python3 -c '
import os
import sys

with open(os.environ["PHOBOS_ARGV_FILE"], "rb") as handle:
    fields = handle.read().split(b"\0")
sys.exit(0 if os.environ["PHOBOS_WANTED"].encode() in fields else 1)
'
}

check_a_fixture_tree_is_pruned() {
    local root output status recorded
    root="$(mktemp -d)"
    build_fixture "${root}"
    install_bwrap_recorder "${root}"
    output="$(run_prune "${root}" 2>&1)"
    status="$?"

    if (( status == 0 )) && the_build_ran "${root}"; then
        ok "the pruner completes against a fixture tree"
    else
        bad "the pruner completes against a fixture tree" "exit 0 and a build that ran" \
            "exit ${status}: ${output}"
        rm -rf "${root}"
        return
    fi

    if argv_holds "${root}/logs/argv" "${root}/target/${AWKWARD_NAME}"; then
        ok "a name full of shell syntax reaches the kernel as one argument"
    else
        bad "a name full of shell syntax reaches the kernel as one argument" \
            "the name as one recorded argument" "it was split, or never reached bwrap"
    fi

    # There is deliberately no check for a file the payload would have created. The old
    # code would have evaluated it inside the per-exercise workroot, which the producer
    # removes as soon as the exercise is done, so such a marker is gone before anything
    # could look for it. The recorded vector above is the evidence: a name that arrives
    # as one argument was never handed to a shell to interpret.

    recorded="$(cat "${root}/out/java_exercise1.paths" 2>/dev/null)"
    if [[ -n "${recorded}" ]]; then
        ok "the run produced an artefact"
    else
        bad "the run produced an artefact" "java_exercise1.paths with content" "missing or empty"
    fi

    # r means readable, n means the build never touched it. Both directions matter: a
    # pruner that keeps everything is useless, and one that drops what a build needs
    # produces a policy that denies a correct submission.
    if grep -qE "^r .*/target/needed$" <<<"${recorded}"; then
        ok "the directory the build reads is kept readable"
    else
        bad "the directory the build reads is kept readable" "r on target/needed" "${recorded}"
    fi

    if grep -qE "^n .*/target/unneeded$" <<<"${recorded}"; then
        ok "the directory nothing reads is marked not required"
    else
        bad "the directory nothing reads is marked not required" "n on target/unneeded" "${recorded}"
    fi

    if grep -qs "target-secret" "${root}/logs/argv" "${root}/out/java_exercise1.paths"; then
        bad "a sibling sharing the target's name is never reached" \
            "target-secret in neither the vector nor the artefact" "it was bound or recorded"
    else
        ok "a sibling sharing the target's name is never reached"
    fi
    rm -rf "${root}"
}

check_the_target_must_be_named() {
    local output status
    output="$("${PRUNER}" --script /bin/true --lang java 2>&1)"
    status="$?"
    if (( status != 0 )) && [[ "${output}" == *"--target is required"* ]]; then
        ok "a prune without --target is refused"
    else
        bad "a prune without --target is refused" "a non-zero exit naming --target" "exit ${status}: ${output}"
    fi
}

check_a_missing_target_is_refused() {
    local output status
    output="$("${PRUNER}" --script /bin/true --lang java --target /nonexistent-"$$" 2>&1)"
    status="$?"
    if (( status != 0 )) && [[ "${output}" == *"--target is not a path that exists"* ]]; then
        ok "a --target that does not exist is refused"
    else
        bad "a --target that does not exist is refused" "a non-zero exit naming the path" "exit ${status}: ${output}"
    fi
}

check_the_host_tmp_is_not_in_the_sandbox() {
    local root marker output status
    root="$(mktemp -d)"
    marker="/tmp/phobos-host-tmp-$$"
    printf 'host\n' >"${marker}"
    build_fixture "${root}"
    install_bwrap_recorder "${root}"
    write_build_script "${root}" "if [ -e \"${marker}\" ]; then echo HOST-TMP-VISIBLE; fi"
    output="$(run_prune "${root}" 2>&1)"
    status="$?"
    if (( status != 0 )); then
        bad "the host /tmp is not inside the sandbox" "a completed prune" "exit ${status}: ${output}"
    elif ! the_build_ran "${root}"; then
        bad "the host /tmp is not inside the sandbox" "a build that ran" "it never ran, so nothing was measured"
    elif grep -qs HOST-TMP-VISIBLE "${root}"/logs/build-*.log; then
        bad "the host /tmp is not inside the sandbox" "the marker unreadable" "the sandbox read it"
    else
        ok "the host /tmp is not inside the sandbox"
    fi
    rm -f "${marker}"
    rm -rf "${root}"
}

check_the_environment_is_not_inherited() {
    local root output status
    root="$(mktemp -d)"
    build_fixture "${root}"
    install_bwrap_recorder "${root}"
    write_build_script "${root}" 'if [ -n "${PHOBOS_SECRET_FOR_TEST:-}" ]; then echo SECRET-VISIBLE; fi'
    output="$(PHOBOS_SECRET_FOR_TEST=leaked run_prune "${root}" 2>&1)"
    status="$?"
    if (( status != 0 )); then
        bad "an unrelated variable does not reach the sandbox" "a completed prune" "exit ${status}: ${output}"
    elif ! the_build_ran "${root}"; then
        bad "an unrelated variable does not reach the sandbox" "a build that ran" "it never ran, so nothing was measured"
    elif grep -qs SECRET-VISIBLE "${root}"/logs/build-*.log; then
        bad "an unrelated variable does not reach the sandbox" "no SECRET-VISIBLE" "the sandbox read it"
    else
        ok "an unrelated variable does not reach the sandbox"
    fi
    rm -rf "${root}"
}

check_the_target_must_be_named
check_a_missing_target_is_refused

if ! bwrap_works; then
    if [[ -n "${PHOBOS_REQUIRE_BWRAP:-}" ]]; then
        bad "bubblewrap can build a sandbox here" "a working sandbox" "the host refused a user namespace"
        summary
    fi
    skip "the checks that run the pruner" "bubblewrap cannot create a user namespace here"
    summary
fi

check_a_fixture_tree_is_pruned
check_the_host_tmp_is_not_in_the_sandbox
check_the_environment_is_not_inherited
summary
