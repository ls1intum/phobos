#!/usr/bin/env bash
# Regression tests for run_minimal_fs_all.sh, the entry point of the prune images.
#
# What it produces becomes an allow-list, so the two ways it can quietly produce
# less than it should both matter: finishing successfully while an exercise's
# artefacts were never written, and leaving an earlier run's artefacts in place so
# that a language which produced nothing still looks like it did.
#
# The pruner itself and the emitter are replaced by stubs, so these checks need no
# bubblewrap, no container and no exercise repository.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PRODUCER="${HERE}/../var/tmp/pruning/run_minimal_fs_all.sh"

passed=0
failed=0

ok() {
    printf 'ok    %s\n' "$1"
    passed=$((passed + 1))
}

bad() {
    printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"
    failed=$((failed + 1))
}

summary() {
    echo
    printf '%d passed, %d failed\n' "${passed}" "${failed}"
    (( failed == 0 )) || exit 1
    exit 0
}

# A prune stub leaves behind the one file the producer looks for afterwards.
write_prune_stub() {
    cat >"$1" <<'STUB'
#!/usr/bin/env bash
# Stands in for detect_minimal_fs.sh, which would need bubblewrap.
printf 'dummy\n' > final_bindings.txt
STUB
    chmod +x "$1"
}

# An emitter stub that writes one artefact per exercise, or fails on request.
write_emit_stub() {
    cat >"$1" <<'STUB'
import os
import sys

arguments = dict(zip(sys.argv[1:-1:2], sys.argv[2::2]))
if os.environ.get("EMIT_MUST_FAIL"):
    sys.exit("stub emitter: refusing")
destination = os.path.join(
    arguments["--out-dir"],
    "{}_{}.paths".format(arguments["--lang"], arguments["--exercise"]),
)
with open(destination, "w", encoding="utf-8") as handle:
    handle.write("r /usr/lib\n")
STUB
    chmod +x "$1"
}

# One language holding one exercise, in the shape the producer expects.
build_fixture() {
    local root="$1" lang="$2"
    mkdir -p "${root}/testing-dir/${lang}/exercise1/assignment" "${root}/helpers" "${root}/out"
    printf '#!/usr/bin/env bash\ntrue\n' >"${root}/testing-dir/${lang}/exercise1/build_script.sh"
    chmod +x "${root}/testing-dir/${lang}/exercise1/build_script.sh"
    write_prune_stub "${root}/prune-stub.sh"
    write_emit_stub "${root}/helpers/emit_artifacts.py"
}

# Runs the producer against a fixture, with every path pointed into it.
run_producer() {
    local root="$1" lang="$2"
    shift 2
    TESTING_DIR="${root}/testing-dir" \
        PRUNE_SCRIPT="${root}/prune-stub.sh" \
        OUTPUT_DIR="${root}/out" \
        HELPER_DIR="${root}/helpers" \
        "$@" \
        bash "${PRODUCER}" "${lang}"
}

check_a_quiet_run_completes() {
    local root
    root="$(mktemp -d)"
    build_fixture "${root}" java
    local output
    output="$(run_producer "${root}" java env 2>&1)"
    local status="$?"
    if (( status == 0 )); then
        ok "a run without --verbose completes"
    else
        bad "a run without --verbose completes" "exit 0" "exit ${status}: ${output}"
    fi
    rm -rf "${root}"
}

check_this_run_s_artefacts_replace_the_last_one_s() {
    local root
    root="$(mktemp -d)"
    build_fixture "${root}" java
    printf 'r /from/an/earlier/run\n' >"${root}/out/java_gone.paths"
    printf 'r /another/language\n' >"${root}/out/python_kept.paths"
    local output
    output="$(run_producer "${root}" java env 2>&1)"
    local status="$?"
    if (( status == 0 )); then
        ok "the run itself succeeds"
    else
        bad "the run itself succeeds" "exit 0" "exit ${status}: ${output}"
    fi
    if [[ -e "${root}/out/java_gone.paths" ]]; then
        bad "an earlier run's artefacts are removed" "java_gone.paths gone" "still present"
    else
        ok "an earlier run's artefacts are removed"
    fi
    if [[ -e "${root}/out/python_kept.paths" ]]; then
        ok "another language's artefacts are left alone"
    else
        bad "another language's artefacts are left alone" "python_kept.paths kept" "removed"
    fi
    if [[ -e "${root}/out/java_exercise1.paths" ]]; then
        ok "this run's artefacts are written"
    else
        bad "this run's artefacts are written" "java_exercise1.paths present" "missing"
    fi
    rm -rf "${root}"
}

check_an_emitter_failure_fails_the_run() {
    local root
    root="$(mktemp -d)"
    build_fixture "${root}" java
    local output
    output="$(run_producer "${root}" java env EMIT_MUST_FAIL=1 2>&1)"
    local status="$?"
    if (( status == 0 )); then
        bad "an emitter failure fails the run" "a non-zero exit" "exit 0: ${output}"
    else
        ok "an emitter failure fails the run"
    fi
    if [[ -n "$(find "${root}/out" -name 'java_*.paths' -print -quit)" ]]; then
        bad "an emitter failure leaves no artefact behind" "no java_*.paths" "one was written"
    else
        ok "an emitter failure leaves no artefact behind"
    fi
    rm -rf "${root}"
}

check_a_quiet_run_completes
check_this_run_s_artefacts_replace_the_last_one_s
check_an_emitter_failure_fails_the_run
summary
