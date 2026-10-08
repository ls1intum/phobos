#!/usr/bin/env bash
# Prunes the Maven reference exercise on the grading layers, reads the result, and shows the wrong
# reasons it must not be fooled by (Task 14.1 of the prune plan).
#
# The exercise is var/tmp/testing-dir/java-maven/maven-reference: Artemis's Maven test template with
# Ares 2, built offline from the repository pre-loaded into the run-phase image. The suite
#   input      re-hashes every file the committed manifest lists first (the image build already held the
#              whole repository to it), since a prune that observed other artefacts than grading reads
#              would be about another image;
#   permitted  prunes the exercise, whose prune.json declares the pre-loaded repository a pinned read root that
#              the pruner checks against its manifest first, merges the result into BaseLanguage-java-maven.cfg and its own file,
#              and has the exercise pass under exactly that pair with every layer on;
#   forbidden  reads the record: both tests passed in all three baseline runs, whose log shows the weaving
#              step and the copy of the Ares runtime jars, every containment check refused, and under /root
#              exactly one directory grant, [read] on the pinned repository with the comment saying why, and
#              otherwise single files that exist, nothing on /root or /root/.m2 and no write-class right
#              under /root/.m2; the rows of the Java seed on /tmp, commented as coming from it, and no
#              write-class right anywhere but /tmp, the working directory and /dev/null, and nothing on /tmp
#              beyond the seed's four sections;
#   wrong reasons  a copy without its tests aborts with no tests run, a copy that pins a version the
#              repository lacks aborts as an infrastructure failure, a copy whose manifest does not match
#              the repository aborts before any run, a copy that does not name the seed aborts for the reason the
#              prune had before the seed existed (a refusal on /tmp survives its grant), and none writes a policy.
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
    cp "${WORK}/prune.log" "${WORK}/merge.log" "${ARTEFACTS_DIR}/" 2>/dev/null
    [[ -d "${WORK}/verify-out" ]] && cp -r "${WORK}/verify-out" "${ARTEFACTS_DIR}/verify-out" 2>/dev/null
    local wrong
    for wrong in "${WORK}/${KEY}"-*; do
      [[ -d "${wrong}" ]] && cp -r "${wrong}" "${ARTEFACTS_DIR}/$(basename "${wrong}")" 2>/dev/null
    done
  fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

# Puts the exercise and the helpers where the prune container has them (A.6.1).
set_up() {
  if [[ ! -f "${MANIFEST}" ]]; then
    echo "no manifest at ${MANIFEST}: mount docker/run_phase/java/maven-repository.sha256 there, read-only" >&2
    exit 1
  fi
  rm -rf "${EXERCISES}" "${HELPERS}"
  mkdir -p "${EXERCISES}/${KEY}"
  cp -r "${REPO}/var/tmp/testing-dir/${KEY}/${EXERCISE}" "${EXERCISES}/${KEY}/${EXERCISE}"
  cp -r "${REPO}/var/tmp/helpers" "${HELPERS}"
}

# Prints the SHA-256 of one file as docker/run_phase/java/pin-repository.sh reckons it: of its content
# without the comment lines for a file named _remote.repositories, which Maven writes beside every
# artefact with a comment holding the time it was written, and of the whole content for any other file.
manifest_digest() {
  local file="$1"
  local sum
  if [[ "${file##*/}" == "_remote.repositories" ]]; then
    sum="$(grep -v '^#' "${file}" | sha256sum)"
  else
    sum="$(sha256sum < "${file}")"
  fi
  printf '%s' "${sum%% *}"
}

# The image carries JDK 25 and exactly the bytes the manifest names. The image build already held the
# repository to the manifest with pin-repository.sh verify, which runs the exercise's online build and so
# needs a network; here, with none, each listed file is hashed again by the same rule, which is what
# makes the prune about the image grading reads.
check_input() {
  local version
  version="$(java -version 2>&1 | head -1)"
  if [[ "${version}" == *'"25'* ]]; then ok "the image runs JDK 25"; else bad "the image runs JDK 25" "${version}"; fi
  local wanted
  local path
  local listed=0
  local wrong=()
  while read -r wanted path; do
    listed=$((listed + 1))
    if [[ ! -f "${REPOSITORY}/${path}" ]]; then
      wrong+=("missing: ${path}")
    elif [[ "$(manifest_digest "${REPOSITORY}/${path}")" != "${wanted}" ]]; then
      wrong+=("differs: ${path}")
    fi
  done < "${MANIFEST}"
  if [[ ${listed} -gt 0 && ${#wrong[@]} -eq 0 ]]; then
    ok "every file of the pre-loaded repository is as the manifest says (${listed} files)"
  else
    bad "every file of the pre-loaded repository is as the manifest says" "${listed} listed; ${wrong[*]:0:5}"
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
import re
import sys

sys.path.insert(0, "/var/tmp/helpers")

import glob

from layer_prune import cfgfile

record = json.load(open(sys.argv[1]))
policy = cfgfile.read_policy(open(sys.argv[2]).read())
baselines = [entry for entry in record["log"] if entry["stage"] == "baseline"]
good = [
    entry for entry in baselines
    if entry["status"] == 0 and entry["verdict"]["exit_class"] == "success" and len(entry["verdict"]["tests"]) == 2
    and all(outcome == "passed" for _, outcome in entry["verdict"]["tests"])
    and {name.rsplit(".", 1)[1].removesuffix("()") for name, _ in entry["verdict"]["tests"]}
    == {"addsTwoNumbers", "addsANegativeNumber"}
    and entry["verdict"]["tests_ran"] and not entry["verdict"]["no_source"] and not entry["verdict"]["infra_failure"]
]
print("baseline", len(baselines), len(good))
logs = sorted(glob.glob("/var/tmp/layer-prune-logs/run-*-direct.log"))
text = open(logs[0], errors="replace").read() if logs else ""
print("ares-log", bool(re.search(r"aspectj[^\n]*:compile", text)) and "copy-ares-runtime-jars" in text)
checks = [entry for entry in record["log"] if entry["stage"] == "containment"][0]["checks"]
refused = sum(1 for check in checks if check["refused"])
unchecked = sum(1 for check in checks if check.get("unchecked"))
print("containment", len(checks), "refused" if refused >= 1 and refused + unchecked == len(checks) else "passed", refused, unchecked)
under_root = {path: sections for path, sections in policy.fs.items() if path == "/root" or path.startswith("/root/")}
not_files = sorted(path for path in under_root if not os.path.isfile(path))
print("root-grants", len(under_root), "not-files", not_files)
print("pinned-sections", sorted(policy.fs.get("/root/.m2/repository", ())))
print("pinned-comment", "pinned: [read] on the directory /root/.m2/repository as one entry" in open(sys.argv[2]).read())
writable = sorted(path for path, sections in under_root.items()
                  if (path == "/root/.m2" or path.startswith("/root/.m2/")) and sections & set(cfgfile.WRITE_SECTIONS))
print("root-writes", writable)
write_class = set(cfgfile.WRITE_SECTIONS)
elsewhere = sorted(path for path, sections in policy.fs.items() if sections & write_class and not (
    path == "/tmp" or path == "/dev/null" or path == "/var/tmp/testing-dir" or path.startswith("/var/tmp/testing-dir/")))
print("writes-elsewhere", elsewhere)
print("tmp-sections", sorted(policy.fs.get("/tmp", ())))
print("tmp-beyond-seed", sorted(set(policy.fs.get("/tmp", ())) - {"read", "write", "create", "delete"}))
print("seed-comment", "come from the java.cfg seed of the prune image, not from a refusal" in open(sys.argv[2]).read())
PY
)"
  check "the baseline holds both test cases, passed, in all three runs, with tests run and no wrong-reason marker" \
    "baseline 3 3" "$(grep '^baseline' <<<"${summary}")"
  check "the baseline log shows the weaving step and the copy of the Ares runtime jars" "ares-log True" \
    "$(grep '^ares-log' <<<"${summary}")"
  if grep -q '^containment [1-9][0-9]* refused [1-9][0-9]* [0-9]*$' <<<"${summary}"; then
    ok "every containment check was refused or is named as unchecked, and at least one was refused"
  else
    bad "every containment check was refused or is named as unchecked, and at least one was refused" "${summary}"
  fi
  if grep -q "^root-grants [1-9][0-9]* not-files \['/root/.m2/repository'\]" <<<"${summary}"; then
    ok "under /root only the pinned repository is a directory grant, every other grant a single file that exists"
  else
    bad "under /root only the pinned repository is a directory grant, every other grant a single file that exists" \
      "$(grep '^root-grants' <<<"${summary}")"
  fi
  check "the pinned repository is granted [read] and nothing else" "pinned-sections ['read']" \
    "$(grep '^pinned-sections' <<<"${summary}")"
  check "the generated policy says why that directory is not granted file by file" "pinned-comment True" \
    "$(grep '^pinned-comment' <<<"${summary}")"
  check "no write-class right is granted under /root/.m2" "root-writes []" "$(grep '^root-writes' <<<"${summary}")"
  check "no write-class right is granted anywhere but /tmp, the working directory and /dev/null" "writes-elsewhere []" \
    "$(grep '^writes-elsewhere' <<<"${summary}")"
  if grep -q "^tmp-sections \[.*'write'.*\]" <<<"${summary}"; then
    ok "the rows of the Java seed that the build needed are in the policy for /tmp"
  else
    bad "the rows of the Java seed that the build needed are in the policy for /tmp" "$(grep '^tmp-sections' <<<"${summary}")"
  fi
  check "the /tmp rows are the seed's four sections at most, which the shipped base grants" "tmp-beyond-seed []" \
    "$(grep '^tmp-beyond-seed' <<<"${summary}")"
  check "the policy says those /tmp rows come from the seed" "seed-comment True" "$(grep '^seed-comment' <<<"${summary}")"
}

# The merged pair passes with every layer on, as grading applies it.
check_merged_and_verified() {
  [[ -f "${CFG}" ]] || { bad "the merged configuration can be checked" "no policy was written"; return; }
  if python3 "${REPO}/docker/prune_phase/orchestrate/orchestrate.py" --langs "${KEY}" --path-dir "${OUTPUT}" \
      --core-dir "${CORE}" --helpers-dir "${HELPERS}" > "${WORK}/merge.log" 2>&1 \
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

# Prunes a copy whose prune.json names a manifest that does not match the repository, and checks that the
# exercise is refused before any run and no policy is written. The manifest is the real one with the sum of
# its first line replaced; the directory is the one the prune container mounts manifests in.
check_tampered_manifest() {
  local key="${KEY}-tampered"
  local manifest_directory=/srv/phobos-manifest
  local tampered="${manifest_directory}/tampered.sha256"
  mkdir -p "${manifest_directory}"
  local first
  first="$(head -1 "${MANIFEST}" | cut -d' ' -f3-)"
  { printf '%064d  %s\n' 0 "${first}"; tail -n +2 "${MANIFEST}"; } > "${tampered}" \
    || { bad "a tampered manifest can be written for the check"; return; }
  rm -rf "${EXERCISES:?}/${key}"
  mkdir -p "${EXERCISES}/${key}"
  cp -r "${EXERCISES}/${KEY}/${EXERCISE}" "${EXERCISES}/${key}/${EXERCISE}"
  sed -i "s|${manifest_directory}/[^\"]*|${tampered}|" "${EXERCISES}/${key}/${EXERCISE}/prune.json"
  local out
  out="$(prune "${key}" "${WORK}/${key}" 2>&1)"
  local status=$?
  local runs
  # A run, the baseline's included, is the record entry that carries the status it ended with; the entries
  # for the seed and the pinned roots, which are made before the first run, do not.
  runs="$(python3 -c 'import json, sys; print(sum("status" in entry for entry in json.load(open(sys.argv[1]))["evidence"]["record"]))' \
    "${WORK}/${key}/${key}_${EXERCISE}.aborted.json" 2>&1)"
  if [[ "${status}" -ne 0 && "${out}" == *"aborted: a pinned read root does not match its manifest"* \
        && "${out}" == *"${first}: its SHA-256 differs from the manifest's"* && "${runs}" == 0 \
        && ! -e "${WORK}/${key}/${key}_${EXERCISE}.cfg" ]]; then
    ok "a copy whose manifest does not match the repository aborts before any run and writes no policy"
  else
    bad "a copy whose manifest does not match the repository aborts before any run and writes no policy" \
      "status ${status}: $(tail -3 <<<"${out}")"
  fi
  rm -f "${tampered}"
}

# Prunes a copy whose prune.json does not name the seed, and checks that it aborts as the prune did before the
# seed existed: the build's scratch files in /tmp are refused and nothing grants them. No policy is written.
check_no_seed() {
  local key="${KEY}-noseed"
  rm -rf "${EXERCISES:?}/${key}"
  mkdir -p "${EXERCISES}/${key}"
  cp -r "${EXERCISES}/${KEY}/${EXERCISE}" "${EXERCISES}/${key}/${EXERCISE}"
  sed -i 's|, "seed": "java.cfg"||' "${EXERCISES}/${key}/${EXERCISE}/prune.json"
  local out
  out="$(prune "${key}" "${WORK}/${key}" 2>&1)"
  local status=$?
  local refused
  refused="$(python3 -c 'import json, sys; print(sorted(json.load(open(sys.argv[1]))["evidence"]["grants"]))' \
    "${WORK}/${key}/${key}_${EXERCISE}.aborted.json" 2>&1)"
  if [[ "${status}" -ne 0 && "${out}" == *"aborted: a refusal survived its own grant"* && "${refused}" == *"'/tmp'"* \
        && ! -e "${WORK}/${key}/${key}_${EXERCISE}.cfg" ]]; then
    ok "a copy that does not name the seed aborts as before, on /tmp, and writes no policy"
  else
    bad "a copy that does not name the seed aborts as before, on /tmp, and writes no policy" \
      "status ${status}, refused ${refused}: $(tail -3 <<<"${out}")"
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
check_tampered_manifest
check_no_seed
finish
