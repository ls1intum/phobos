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
# How the pruner reads a build's outcome, the NO-SOURCE rule among it, is checked through
# a bwrap that builds no sandbox, so those checks run on any machine with bash and python3.
#
# Bubblewrap needs an unprivileged user namespace. Where the host refuses one the
# checks that need it are skipped, unless PHOBOS_REQUIRE_BWRAP is set, which turns that
# skip into a failure. Anything that would otherwise read a skip as a pass should set it.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harness.sh
source "${HERE}/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
PRODUCER="${HERE}/../var/tmp/pruning/run_minimal_fs_all.sh"
PRUNER="${HERE}/../var/tmp/pruning/detect_minimal_fs.sh"

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

# The sibling just outside the target that nothing in the run may reach: same prefix as the
# target, one level up. A prune that matched the target's name rather than descending into
# it would take this with it.
build_prefix_sibling() {
  local root="$1"
  mkdir -p "${root}/target-secret/private"
  printf 'not for the sandbox\n' >"${root}/target-secret/private/secret.txt"
}

# A tree to prune, an exercise whose build script needs one part of it, and a sibling
# just outside the target that nothing in the run may reach.
build_fixture() {
  local root="$1"
  mkdir -p "${root}/target/needed" "${root}/target/unneeded" "${root}/helpers"
  mkdir -p "${root}/logs" "${root}/scratch" "${root}/out"
  mkdir -p "${root}/testing-dir/java/exercise1/assignment"
  mkdir -p "${root}/target/${AWKWARD_NAME}"
  build_prefix_sibling "${root}"
  printf 'the build reads this\n' >"${root}/target/needed/input.txt"
  printf 'nothing reads this\n' >"${root}/target/unneeded/spare.txt"

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
  local root="$1"
  local extra="$2"
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
  local root="$1"
  local real
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

# Whether the recorded artefact marks the read directory readable and the untouched one
# not required. r means readable, n means the build never touched it. Both directions
# matter: a pruner that keeps everything is useless, and one that drops what a build needs
# produces a policy that denies a correct submission.
check_the_artefact_marks_both_directions() {
  local recorded="$1"
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
}

# There is deliberately no check for a file the payload would have created. The old code
# would have evaluated it inside the per-exercise workroot, which the producer removes as
# soon as the exercise is done, so such a marker is gone before anything could look for
# it. The recorded vector is the evidence: a name that arrives as one argument was never
# handed to a shell to interpret.
check_a_fixture_tree_is_pruned() {
  local root
  local output
  local status
  local recorded
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

  recorded="$(cat "${root}/out/java_exercise1.paths" 2>/dev/null)"
  if [[ -n "${recorded}" ]]; then
    ok "the run produced an artefact"
  else
    bad "the run produced an artefact" "java_exercise1.paths with content" "missing or empty"
  fi

  check_the_artefact_marks_both_directions "${recorded}"

  if grep -qs "target-secret" "${root}/logs/argv" "${root}/out/java_exercise1.paths"; then
    bad "a sibling sharing the target's name is never reached" \
      "target-secret in neither the vector nor the artefact" "it was bound or recorded"
  else
    ok "a sibling sharing the target's name is never reached"
  fi
  rm -rf "${root}"
}

check_the_target_must_be_named() {
  local output
  local status
  output="$("${PRUNER}" --script /bin/true --lang java 2>&1)"
  status="$?"
  if (( status != 0 )) && [[ "${output}" == *"--target is required"* ]]; then
    ok "a prune without --target is refused"
  else
    bad "a prune without --target is refused" "a non-zero exit naming --target" "exit ${status}: ${output}"
  fi
}

check_a_missing_target_is_refused() {
  local output
  local status
  output="$("${PRUNER}" --script /bin/true --lang java --target /nonexistent-"$$" 2>&1)"
  status="$?"
  if (( status != 0 )) && [[ "${output}" == *"--target is not a path that exists"* ]]; then
    ok "a --target that does not exist is refused"
  else
    bad "a --target that does not exist is refused" "a non-zero exit naming the path" "exit ${status}: ${output}"
  fi
}

check_the_host_tmp_is_not_in_the_sandbox() {
  local root
  local marker
  local output
  local status
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
  local root
  local output
  local status
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

# A bwrap on PATH that builds no sandbox at all. It writes the paths this invocation would
# hide to logs/hidden, one per line, maps the exercise binding back onto the host copy and
# runs the build script there. The checks that use it measure how the pruner classifies a
# build's outcome, never what a sandbox contains, which is why they can run where
# Bubblewrap cannot. An option it does not know stops it, so that a change to the pruner's
# invocation cannot be misread quietly.
install_passthrough_bwrap() {
  local root="$1"
  mkdir -p "${root}/bin"
  cat >"${root}/bin/bwrap" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
hidden="${root}/logs/hidden"
exercise="/var/tmp/testing-dir"
host=""
directory=""
# The status this stand-in ends with when it is handed something the pruner would never pass;
# chosen outside what a build or bwrap itself returns, so the suite can tell the two apart.
STUB_REFUSED_EXIT=97
: >"${hidden}"
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --tmpfs)
            printf '%s\n' "$2" >>"${hidden}"
            shift 2
            ;;
        --bind)
            if [[ "$3" == "${exercise}" ]]; then host="$2"; fi
            shift 3
            ;;
        --ro-bind|--setenv)
            shift 3
            ;;
        --chdir)
            directory="$2"
            shift 2
            ;;
        --dir|--proc|--dev)
            shift 2
            ;;
        --clearenv|--share-net|--new-session|--unshare-pid|--unshare-uts|--unshare-ipc)
            shift
            ;;
        *)
            printf 'pass-through bwrap: unknown option %s\n' "$1" >&2
            exit "${STUB_REFUSED_EXIT}"
            ;;
    esac
done
[[ -n "${host}" ]] || { printf 'pass-through bwrap: no binding for %s\n' "${exercise}" >&2; exit "${STUB_REFUSED_EXIT}"; }
cd -- "${host}${directory#"${exercise}"}"
exec "$1" "${host}${2#"${exercise}"}"
STUB
  chmod +x "${root}/bin/bwrap"
}

# The line that stands in for Gradle compiling nothing: when this invocation hides
# target/needed, the build prints the NO-SOURCE line Gradle prints and ends with the given
# status, and otherwise carries on to its ordinary lines.
no_source_build_line() {
  local root="$1"
  local status="$2"
  printf "if grep -qxF '%s' '%s'; then echo '> Task :compileJava NO-SOURCE'; exit %s; fi" \
    "${root}/target/needed" "${root}/logs/hidden" "${status}"
}

# Prunes a fixture through the pass-through bwrap, with a build that behaves as the named
# outcome and with any NAME=VALUE arguments set for the run. Prints the exit status on the
# first line, then one "log: NAME" line per build log the pruner left followed by that
# log's lines indented with "  | ", then the artefact the run wrote. The logs are named
# after each attempt and its verdict and hold what the build printed, so they show where a
# run stopped and whether the build ran at all, which an exit status alone cannot.
classify() {
  local outcome="$1"
  shift
  local root
  local line
  local status
  local assignment
  local log
  root="$(mktemp -d)"
  build_fixture "${root}"
  install_passthrough_bwrap "${root}"
  case "${outcome}" in
    no-source-success) line="$(no_source_build_line "${root}" 0)" ;;
    no-source-failure) line="$(no_source_build_line "${root}" 1)" ;;
    failing-tests) line="echo 'There were failing tests'; exit 1" ;;
  esac
  write_build_script "${root}" "${line}"
  (
    for assignment in "$@"; do export "${assignment?}"; done
    run_prune "${root}"
  ) >/dev/null 2>&1
  status="$?"
  printf '%s\n' "${status}"
  for log in "${root}"/logs/build-*.log; do
    [[ -e "${log}" ]] || continue
    printf 'log: %s\n' "$(basename -- "${log}")"
    sed 's/^/  | /' "${log}"
  done
  cat "${root}/out/java_exercise1.paths" 2>/dev/null
  rm -rf "${root}"
}

# Whether a classification finished with status 0 and recorded the given mode on the
# given directory of the fixture's target.
classified_as() {
  local result="$1"
  local mode="$2"
  local directory="$3"
  [[ "${result%%$'\n'*}" == "0" ]] && grep -qE "^${mode} .*/target/${directory}$" <<<"${result}"
}

check_a_build_that_compiles_nothing_keeps_its_source() {
  local result
  result="$(classify no-source-success)"
  if classified_as "${result}" r needed; then
    ok "a build that compiles nothing and exits zero keeps what it reads readable"
  else
    bad "a build that compiles nothing and exits zero keeps what it reads readable" \
      "exit 0 and r on target/needed" "${result}"
  fi

  result="$(classify no-source-success UNIGNORABLE_SUCCESS_PATTERNS='a^')"
  if classified_as "${result}" n needed; then
    ok "without the NO-SOURCE rule the same build would hide what it reads"
  else
    bad "without the NO-SOURCE rule the same build would hide what it reads" \
      "exit 0 and n on target/needed, which shows the rule is what keeps it" "${result}"
  fi

  result="$(classify no-source-failure)"
  if classified_as "${result}" r needed; then
    ok "a build that compiles nothing and fails keeps what it reads readable"
  else
    bad "a build that compiles nothing and fails keeps what it reads readable" \
      "exit 0 and r on target/needed" "${result}"
  fi
}

check_failing_tests_are_not_a_missing_resource() {
  local result
  result="$(classify failing-tests)"
  if classified_as "${result}" n unneeded; then
    ok "failing tests alone do not make a directory needed"
  else
    bad "failing tests alone do not make a directory needed" \
      "exit 0 and n on target/unneeded" "${result}"
  fi

  result="$(classify failing-tests IGNORABLE_FAILURE_PATTERNS='a^')"
  if [[ "${result%%$'\n'*}" == "1" ]] \
       && grep -qx "log: build-1-fail.log" <<<"${result}" \
       && grep -qx "  | There were failing tests" <<<"${result}" \
       && ! grep -q "^log: build-2" <<<"${result}" \
       && ! grep -qE "^[nrw] " <<<"${result}"; then
    ok "without the failing-tests rule such a build cannot be pruned at all"
  else
    bad "without the failing-tests rule such a build cannot be pruned at all" \
      "exit 1 after one failed attempt with every directory writable, and no artefact" "${result}"
  fi
}

check_the_target_must_be_named
check_a_missing_target_is_refused
check_a_build_that_compiles_nothing_keeps_its_source
check_failing_tests_are_not_a_missing_resource

if ! bwrap_works; then
  if [[ -n "${PHOBOS_REQUIRE_BWRAP:-}" ]]; then
    bad "bubblewrap can build a sandbox here" "a working sandbox" "the host refused a user namespace"
    finish
  fi
  skip "the checks that run the pruner" "bubblewrap cannot create a user namespace here"
  finish
fi

check_a_fixture_tree_is_pruned
check_the_host_tmp_is_not_in_the_sandbox
check_the_environment_is_not_inherited

finish
