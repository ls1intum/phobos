#!/usr/bin/env bash
# Prunes the Maven reference exercise on the grading layers, reads the result, and shows the two wrong
# reasons it must not be fooled by (Task 14.1 of the prune plan).
#
# The exercise is var/tmp/testing-dir/java-maven/maven-reference: Artemis's Maven test template with
# Ares 2, built offline from the repository pre-loaded into the run-phase image. The suite
#   input      holds the image to its committed manifest first, since a prune that observed other
#              artefacts than grading reads would be about another image;
#   permitted  prunes the exercise, merges the result into BaseLanguage-java-maven.cfg and its own file,
#              and has the exercise pass under exactly that pair with every layer on;
#   forbidden  reads the record: both tests passed in all three baseline runs, every containment check
#              refused, every grant under /root a single file that exists (never a directory), and no
#              write-class right under /root/.m2;
#   wrong reasons  a copy without its tests aborts with no tests run, a copy that pins a version the
#              repository lacks aborts as an infrastructure failure, and neither writes a policy.
#
# Runs inside the prune image built on the run-phase image of this branch, with the repository mounted at
# /repo read-only, in an ordinary container: --network none, cgroup limits, and no --privileged, no
# --cap-add, no --security-opt. When ARTEFACTS_DIR names a writable directory, the artefacts are copied
# there for the caller to keep.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

PHOBOS_HOME="${PHOBOS_HOME:-/var/tmp/opt/core}"
REPO="$(cd -- "${HERE}/../.." && pwd)"
HELPERS=/var/tmp/helpers
EXERCISES=/srv/phobos-prune-exercises
KEY=java-maven
EXERCISE=maven-reference
MANIFEST="${MANIFEST:-/srv/phobos-manifest/maven-repository.sha256}"
REPOSITORY=/root/.m2/repository
WORK="$(mktemp -d /var/tmp/layer-prune-maven.XXXXXX)" || { echo "cannot create a working directory" >&2; exit 1; }
OUTPUT="${WORK}/out"
CORE="${WORK}/core"
CFG="${OUTPUT}/${KEY}_${EXERCISE}.cfg"
RECORD="${OUTPUT}/${KEY}_${EXERCISE}.json"

# Keeps the artefacts where the caller asked, and removes the working directory however the suite ends.
cleanup() {
  if [[ -n "${ARTEFACTS_DIR:-}" && -d "${ARTEFACTS_DIR}" ]]; then
    cp -r "${OUTPUT}/." "${ARTEFACTS_DIR}/" 2>/dev/null
    [[ -d "${CORE}" ]] && cp -r "${CORE}" "${ARTEFACTS_DIR}/core" 2>/dev/null
  fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

# Puts the exercise and the helpers where the prune container has them (A.6.1).
set_up() {
  if [[ ! -f "${MANIFEST}" ]]; then
    MANIFEST="${REPO}/docker/run_phase/java/maven-repository.sha256"
  fi
  rm -rf "${EXERCISES}" "${HELPERS}"
  mkdir -p "${EXERCISES}/${KEY}"
  cp -r "${REPO}/var/tmp/testing-dir/${KEY}/${EXERCISE}" "${EXERCISES}/${KEY}/${EXERCISE}"
  cp -r "${REPO}/var/tmp/helpers" "${HELPERS}"
}

# The image carries JDK 25 and exactly the bytes the manifest names.
check_input() {
  local version
  version="$(java -version 2>&1 | head -1)"
  if [[ "${version}" == *'"25'* ]]; then ok "the image runs JDK 25"; else bad "the image runs JDK 25" "${version}"; fi
  local verified
  verified="$(cd "${REPOSITORY}" && sha256sum --strict -c "${MANIFEST}" 2>&1)"
  local status=$?
  if [[ ${status} -eq 0 && "$(grep -vc ': OK$' <<<"${verified}")" -eq 0 ]]; then
    ok "every file of the pre-loaded repository is as the manifest says ($(wc -l < "${MANIFEST}") files)"
  else
    bad "every file of the pre-loaded repository is as the manifest says" "$(grep -v ': OK$' <<<"${verified}" | head -5)"
  fi
}

# Runs the pruner on the key $1 into the directory $2.
prune() {
  python3 "${HELPERS}/layer_prune/main.py" --stage all --output-dir "$2" "$1"
}

# Reads the record: the baseline, the containment checks and every grant under /root.
check_record() {
  [[ -f "${RECORD}" && -f "${CFG}" ]] || { bad "the record can be read" "no record or no policy was written"; return; }
  local summary
  summary="$(python3 - "${RECORD}" "${CFG}" <<'PY'
import json
import os
import sys

sys.path.insert(0, "/var/tmp/helpers")

from layer_prune import cfgfile

record = json.load(open(sys.argv[1]))
policy = cfgfile.read_policy(open(sys.argv[2]).read())
baselines = [entry for entry in record["log"] if entry["stage"] == "baseline"]
good = [
    entry for entry in baselines
    if len(entry["verdict"]["tests"]) == 2
    and all(outcome == "passed" for _, outcome in entry["verdict"]["tests"])
    and {name.rsplit(".", 1)[1] for name, _ in entry["verdict"]["tests"]} == {"addsTwoNumbers", "addsANegativeNumber"}
    and entry["verdict"]["tests_ran"] and not entry["verdict"]["no_source"] and not entry["verdict"]["infra_failure"]
]
print("baseline", len(baselines), len(good))
checks = [entry for entry in record["log"] if entry["stage"] == "containment"][0]["checks"]
print("containment", len(checks), "refused" if all(check["refused"] or check.get("unchecked") for check in checks) else "passed")
under_root = {path: sections for path, sections in policy.fs.items() if path == "/root" or path.startswith("/root/")}
directories = sorted(path for path in under_root if os.path.isdir(path))
print("root-grants", len(under_root), "directories", directories)
write_class = {"write", "create", "create-ipc", "create-symlink", "delete", "restructure"}
writable = sorted(path for path, sections in under_root.items() if sections & write_class)
print("root-writes", writable)
PY
)"
  check "the baseline holds both test cases, passed, in all three runs, with tests run and no wrong-reason marker" \
    "baseline 3 3" "$(grep '^baseline' <<<"${summary}")"
  if grep -q '^containment [0-9]* refused' <<<"${summary}"; then
    ok "every containment check was refused"
  else
    bad "every containment check was refused" "${summary}"
  fi
  if grep -q '^root-grants [1-9][0-9]* directories \[\]' <<<"${summary}"; then
    ok "every grant under /root is a single file, never a directory"
  else
    bad "every grant under /root is a single file, never a directory" "$(grep '^root-grants' <<<"${summary}")"
  fi
  check "no write-class right is granted under /root" "root-writes []" "$(grep '^root-writes' <<<"${summary}")"
}

# The merged pair passes with every layer on, as grading applies it.
check_merged_and_verified() {
  [[ -f "${CFG}" ]] || { bad "the merged configuration can be checked" "no policy was written"; return; }
  if python3 "${REPO}/docker/prune_phase/orchestrate/orchestrate.py" --langs "${KEY}" --path-dir "${OUTPUT}" \
      --core-dir "${CORE}" --helpers-dir "${HELPERS}" --skip-prune > "${WORK}/merge.log" 2>&1 \
      && [[ -f "${CORE}/BaseLanguage-${KEY}.cfg" && -f "${CORE}/exercises/${KEY}_${EXERCISE}.cfg" ]]; then
    ok "the orchestrator merges the artefact into BaseLanguage-${KEY}.cfg and the exercise's own file"
  else
    bad "the orchestrator merges the artefact into BaseLanguage-${KEY}.cfg and the exercise's own file" \
      "$(tail -5 "${WORK}/merge.log")"
    return
  fi
  local out
  out="$(python3 "${HELPERS}/layer_prune/main.py" --verify "${CORE}" --output-dir "${WORK}/verify-out" "${KEY}" 2>&1)"
  if [[ $? -eq 0 && "${out}" == *"${KEY}/${EXERCISE}: verified"* ]]; then
    ok "the exercise passes under the merged base and its own file, every layer on"
  else
    bad "the exercise passes under the merged base and its own file, every layer on" "$(tail -3 <<<"${out}")"
  fi
}

# Prunes a changed copy of the exercise under another key and checks that it aborts for the reason and
# writes no policy. $1 names the case, $2 the key suffix, $3 the reason the abort must name, $4 the
# field of the baseline verdict it must show, then the command that changes the copy.
check_wrong_reason() {
  local name="$1"
  local suffix="$2"
  local reason="$3"
  local field="$4"
  shift 4
  local key="${KEY}-${suffix}"
  rm -rf "${EXERCISES:?}/${key}"
  mkdir -p "${EXERCISES}/${key}"
  cp -r "${EXERCISES}/${KEY}/${EXERCISE}" "${EXERCISES}/${key}/${EXERCISE}"
  (cd "${EXERCISES}/${key}/${EXERCISE}" && "$@")
  local out
  out="$(prune "${key}" "${WORK}/${key}" 2>&1)"
  local status=$?
  local evidence=""
  [[ -f "${WORK}/${key}/${key}_${EXERCISE}.aborted.json" ]] \
    && evidence="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["evidence"]["verdict"].get(sys.argv[2]))' \
      "${WORK}/${key}/${key}_${EXERCISE}.aborted.json" "${field}" 2>&1)"
  if [[ "${status}" -ne 0 && "${out}" == *"aborted: ${reason}"* && "${evidence}" == "True" \
        && ! -e "${WORK}/${key}/${key}_${EXERCISE}.cfg" ]]; then
    ok "${name}"
  else
    bad "${name}" "status ${status}, ${field}=${evidence}: $(tail -3 <<<"${out}")"
  fi
}

set_up
check_input
prune "${KEY}" "${OUTPUT}" > "${WORK}/prune.log" 2>&1
status=$?
check "the pruner ends with status 0 on the Maven reference exercise" "0" "${status}"
[[ "${status}" -eq 0 ]] || sed 's/^/    /' "${WORK}/prune.log" | tail -20
check_record
check_merged_and_verified
check_wrong_reason "a copy without its tests aborts with no tests run and writes no policy" no-tests \
  "the reference run ran no tests" no_source rm -rf test
check_wrong_reason "a copy that pins a version the repository lacks aborts as an infrastructure failure" missing-ares \
  "the reference run ran no tests" infra_failure sed -i 's|<ares.version>[^<]*</ares.version>|<ares.version>0.0.0-absent</ares.version>|' pom.xml
finish
