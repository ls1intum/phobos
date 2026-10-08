#!/usr/bin/env bash
# Prunes the fixture exercise on the grading layers and holds the derived policy to both directions.
#
# The layer pruner derives a policy from what the layers refuse a reference run. This suite runs the
# whole pipeline (baseline, permissive run, filesystem, network, limits, joint verification,
# containment checks) on tests/integration/layer-prune-fixture and checks the result the way
# grading would meet it:
#   permitted  the fixture's build passes under phobos.sh with the derived policy and every layer on,
#              and its read of /proc/self/status is granted as a per-run name, with its comment;
#   forbidden  under the same policy the probe is refused the unneeded file, the optional file the
#              build did without, a sibling of a granted prefix, a write into what was only read,
#              10.0.0.1:80 and port 8080, and each derived limit ends a run that exceeds it;
#   merged     the orchestrator merges the artefacts into BaseLanguage-java.cfg and the exercise's
#              own file, and the fixture passes under that pair (main.py --verify), as grading applies it,
#              while a base without the needed file's grant fails it; a hand-edited .cfg its record does
#              not vouch for stops the merge. The verification runs in the container the prune ran in,
#              whose index holds what the prune's last run left, which Compose's fresh verify_java
#              container would not;
#   wrong reasons  a flaky reference, NO-SOURCE, a needed setsid, a needed external host and a
#              failure no refused call explains each abort the exercise and write no policy.
#
# Runs inside the prune image with the repository mounted at /repo, read-only, in an ordinary
# container: --network none, cgroup limits, and no --privileged, no --cap-add, no --security-opt.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

PHOBOS_HOME="${PHOBOS_HOME:-/var/tmp/opt/core}"
REPO="$(cd -- "${HERE}/../.." && pwd)"
HELPERS=/var/tmp/helpers
EXERCISES=/srv/phobos-prune-exercises
PROBE=/usr/local/libexec/phobos-prune-probe
WORK="$(mktemp -d /var/tmp/layer-prune-suite.XXXXXX)" || { echo "cannot create a working directory" >&2; exit 1; }
OUTPUT="${WORK}/out"
CFG="${OUTPUT}/java_fixture.cfg"
PROBE_CFG="${WORK}/probe.cfg"

# Removes the working directory however the suite ends.
cleanup() {
  rm -rf "${WORK}"
}
trap cleanup EXIT

# Lays out what the fixture reads and must not read, and the exercise and the helpers where the
# prune container has them (A.6.1).
set_up() {
  mkdir -p /srv/prune-fixture/needed /srv/prune-fixture/optional /srv/prune-fixture/unneeded /srv/prune-fixture-secret
  printf 'needed\n' > /srv/prune-fixture/needed/data.txt
  printf 'maybe\n' > /srv/prune-fixture/optional/maybe.txt
  printf 'secret\n' > /srv/prune-fixture/unneeded/secret.txt
  printf 'secret\n' > /srv/prune-fixture-secret/x
  rm -rf "${EXERCISES}" "${HELPERS}"
  mkdir -p "${EXERCISES}/java"
  cp -r "${REPO}/tests/integration/layer-prune-fixture" "${EXERCISES}/java/fixture"
  cp -r "${REPO}/var/tmp/helpers" "${HELPERS}"
  printf '[read]\n%s\n/dev/null\n\n[execute]\n%s\n' "${PROBE}" "${PROBE}" > "${PROBE_CFG}"
}

# Runs the pruner on the key named by $1 into the directory $2, with the environment given after it.
prune() {
  local key="$1"
  local output="$2"
  shift 2
  env "$@" python3 "${HELPERS}/layer_prune/main.py" --stage all --output-dir "${output}" "${key}"
}

# Prints the probe's output for one operation under the derived policy.
probe_under_policy() {
  "${PHOBOS_HOME}/phobos.sh" --config "${CFG}" --config "${PROBE_CFG}" -- "${PROBE}" "$@" 2>&1
}

# The derived policy exists and the fixture's build passes under it with every layer on.
check_permitted() {
  if [[ -f "${CFG}" ]]; then ok "the pruner wrote java_fixture.cfg"; else bad "the pruner wrote java_fixture.cfg"; return; fi
  rm -rf /var/tmp/testing-dir
  cp -r "${EXERCISES}/java/fixture" /var/tmp/testing-dir
  (cd /var/tmp/testing-dir && "${PHOBOS_HOME}/phobos.sh" --config "${CFG}" -- /bin/bash ./build_script.sh) >"${WORK}/build.log" 2>&1
  local report=/var/tmp/testing-dir/build/test-results/test/TEST-fixture.xml
  if [[ -f "${report}" ]] && ! grep -q '<failure' "${report}" && [[ "$(grep -c '<testcase' "${report}")" -eq 6 ]]; then
    ok "the fixture's build passes every test under the derived policy with every layer on"
  else
    bad "the fixture's build passes every test under the derived policy with every layer on" "$(tail -5 "${WORK}/build.log")"
  fi
  if sed -n '/^\[read\]/,/^$/p' "${CFG}" | grep -qx '/proc' && grep -q '^# .*<pid>' "${CFG}"; then
    ok "the read of /proc/self/status is granted as a per-run name on /proc, with the comment saying so"
  else
    bad "the read of /proc/self/status is granted as a per-run name on /proc, with the comment saying so" "$(cat "${CFG}")"
  fi
  if grep -qx 'allow 127.0.0.1:\*' "${CFG}" && grep -qx 'allow 0' "${CFG}"; then
    ok "the derived policy carries the loopback wildcard and port 0 the fixture's server needs"
  else
    bad "the derived policy carries the loopback wildcard and port 0 the fixture's server needs" "$(cat "${CFG}")"
  fi
}

# Checks that the probe, asked for one operation, prints a refusal with the errno $2.
expect_refused() {
  local name="$1"
  local errno="$2"
  shift 2
  local out
  out="$(probe_under_policy "$@")"
  if grep -q "ret=-1 errno=${errno}" <<<"${out}"; then ok "${name}"; else bad "${name}" "${out}"; fi
}

# What the fixture did not need stays denied, and what it needed is the narrowest grant that works.
check_forbidden() {
  [[ -f "${CFG}" ]] || { bad "the forbidden direction can be checked" "no policy was written"; return; }
  expect_refused "the unneeded file is refused" EACCES read /srv/prune-fixture/unneeded/secret.txt
  expect_refused "the optional file the build did without is refused" EACCES read /srv/prune-fixture/optional/maybe.txt
  expect_refused "a sibling sharing the granted prefix is refused" EACCES read /srv/prune-fixture-secret/x
  expect_refused "the needed file cannot be written, only read" EACCES write /srv/prune-fixture/needed/data.txt x
  expect_refused "10.0.0.1:80 is refused" EACCES tcp 10.0.0.1 80
  expect_refused "binding port 8080 is refused" EACCES bind 127.0.0.1 8080 tcp
  if probe_under_policy read /srv/prune-fixture/needed/data.txt | grep -qE '^OP open ret=[0-9]'; then
    ok "the needed file is still readable"
  else
    bad "the needed file is still readable" "$(probe_under_policy read /srv/prune-fixture/needed/data.txt)"
  fi
  local written
  written="$(sed -n '/^\[\(write\|create\|create-ipc\|create-symlink\|delete\|restructure\)\]/,/^$/p' "${CFG}" \
    | grep '^/' | sort -u | tr '\n' ' ')"
  check "the write-class sections name only the working directory and /dev/null" \
    "/dev/null /var/tmp/testing-dir " "${written}"
}

# Every derived limit is below its default, and the record shows every containment check refused.
check_limits_and_containment() {
  local record="${OUTPUT}/java_fixture.json"
  [[ -f "${record}" ]] || { bad "the record can be read" "no record was written"; return; }
  local summary
  summary="$(python3 - "${record}" "${PHOBOS_HOME}/phobos-tools-common/phobos-constants.sh" <<'PY'
import json
import re
import sys

record = json.load(open(sys.argv[1]))
constants = open(sys.argv[2]).read()
defaults = {"timeout": "PHB_DEFAULT_TIMEOUT_SECONDS", "cpu": "PHB_DEFAULT_LIMIT_CPU", "nproc": "PHB_DEFAULT_LIMIT_NPROC",
            "nofile": "PHB_DEFAULT_LIMIT_NOFILE", "fsize_mb": "PHB_DEFAULT_LIMIT_FSIZE_MB", "mem_mb": "PHB_DEFAULT_LIMIT_MEM_MB"}
limits = record["policy"]["limits"]
lower = all(0 < value < int(re.search(rf"^{defaults[key]}=(\d+)", constants, re.M).group(1)) for key, value in limits.items())
print("limits", sorted(limits), "lower" if lower else "not-lower")
checks = [entry for entry in record["log"] if entry["stage"] == "containment"][0]["checks"]
print("checks", len(checks), "refused" if all(check["refused"] or check.get("unchecked") for check in checks) else "passed")
print("names", sorted(check["name"] for check in checks))
widened = {entry["path"]: entry for entry in [item for item in record["log"] if item["stage"] == "widenings"][-1]["grants"]}
needed = widened.get("/srv/prune-fixture/needed", {})
print("widening", needed.get("observed"), needed.get("covers"))
PY
)"
  check "the record lists the directory grant on needed/ as a widening, with the file behind it and what it covers" \
    "widening ['/srv/prune-fixture/needed/data.txt'] 1" "$(grep '^widening' <<<"${summary}")"
  check "five limits are derived (not mem_mb, the heap is not pinned), each below its default" \
    "limits ['cpu', 'fsize_mb', 'nofile', 'nproc', 'timeout'] lower" "$(grep '^limits' <<<"${summary}")"
  if grep -q '^checks [0-9]* refused' <<<"${summary}" && grep -q "timeout" <<<"${summary}" \
    && grep -q "canary /root/phobos-prune-canary" <<<"${summary}"; then
    ok "the record shows every containment check refused, the canaries and the limits among them"
  else
    bad "the record shows every containment check refused, the canaries and the limits among them" "${summary}"
  fi
}

# The containment check does catch a widened policy: the derived one, hand-edited to grant /srv,
# lets the probe read the canary under /srv, and run_checks aborts on it.
check_containment_catches_a_widening() {
  [[ -f "${CFG}" ]] || { bad "a widened policy fails its containment check" "no policy was written"; return; }
  local out
  out="$(python3 - "${CFG}" <<'PY' 2>&1
import dataclasses
import sys

sys.path.insert(0, "/var/tmp/helpers")

from layer_prune import cfgfile, containment, runner, search

derived = cfgfile.read_policy(open(sys.argv[1]).read())
widened = dataclasses.replace(derived, fs={**derived.fs, "/srv": frozenset({"read"})})
canary = [check for check in containment.checks(widened) if check.name == "canary /srv/phobos-prune-canary/secret"]
original = containment.checks
containment.checks = lambda policy: canary
try:
    containment.run_checks(widened, runner.Environment())
    print("no abort")
except search.PruneAbort as abort:
    print(abort.reason)
finally:
    containment.checks = original
PY
)"
  check "a policy hand-edited to grant /srv fails the canary check" \
    "containment check passed: canary /srv/phobos-prune-canary/secret" "$(tail -1 <<<"${out}")"
}

# The orchestrator merges the artefacts, the fixture passes under the merged pair, and an artefact its
# record does not vouch for stops the merge.
check_merged_and_verified() {
  [[ -f "${CFG}" ]] || { bad "the merged configuration can be checked" "no policy was written"; return; }
  local core="${WORK}/core"
  if python3 "${REPO}/docker/prune_phase/orchestrate/orchestrate.py" --langs java --path-dir "${OUTPUT}" \
      --core-dir "${core}" --helpers-dir "${HELPERS}" --skip-prune >"${WORK}/merge.log" 2>&1 \
      && [[ -f "${core}/BaseLanguage-java.cfg" ]] && ! grep -q '^\[limits\]' "${core}/BaseLanguage-java.cfg" \
      && grep -q '^\[limits\]' "${core}/exercises/java_fixture.cfg"; then
    ok "the orchestrator merges the artefacts into a base without limits and the exercise's own file with them"
  else
    bad "the orchestrator merges the artefacts into a base without limits and the exercise's own file with them" \
      "$(tail -5 "${WORK}/merge.log")"
  fi
  local out
  out="$(python3 "${HELPERS}/layer_prune/main.py" --verify "${core}" --output-dir "${WORK}/verify-out" java 2>&1)"
  if [[ $? -eq 0 && "${out}" == *"java/fixture: verified"* ]]; then
    ok "the fixture passes under the merged base and its own file, every layer on"
  else
    bad "the fixture passes under the merged base and its own file, every layer on" "$(tail -3 <<<"${out}")"
  fi
  local narrowed="${WORK}/core-narrowed"
  cp -r "${core}" "${narrowed}"
  sed -i '\|^/srv/prune-fixture/needed|d' "${narrowed}/BaseLanguage-java.cfg"
  out="$(python3 "${HELPERS}/layer_prune/main.py" --verify "${narrowed}" --output-dir "${WORK}/verify-narrowed" java 2>&1)"
  local narrowed_status=$?
  if [[ ${narrowed_status} -ne 0 && "${out}" == *"java/fixture: aborted: a run under the merged base"*"did not match"* ]] \
      && grep -q '"verified": false' "${WORK}/verify-narrowed/verify/java_fixture.json"; then
    ok "a merged base without the needed file's grant fails the verification"
  else
    bad "a merged base without the needed file's grant fails the verification" "status ${narrowed_status}: $(tail -3 <<<"${out}")"
  fi
  local tampered="${WORK}/tampered"
  cp -r "${OUTPUT}" "${tampered}"
  printf '[read]\n/\n' >> "${tampered}/java_fixture.cfg"
  if python3 "${REPO}/docker/prune_phase/orchestrate/orchestrate.py" --langs java --path-dir "${tampered}" \
      --core-dir "${WORK}/core-tampered" --helpers-dir "${HELPERS}" --skip-prune >"${WORK}/tampered.log" 2>&1; then
    bad "a .cfg its record does not vouch for stops the merge" "the orchestrator merged it"
  elif grep -q 'its SHA-256 differs' "${WORK}/tampered.log"; then
    ok "a .cfg its record does not vouch for stops the merge"
  else
    bad "a .cfg its record does not vouch for stops the merge" "$(tail -3 "${WORK}/tampered.log")"
  fi
}

# Each wrong-reason variant aborts with its reason and writes no policy.
check_wrong_reasons() {
  local variant
  local reason
  local key
  for variant in "FIXTURE_FLAKY:flaky reference" "FIXTURE_NO_SOURCE:ran no tests" \
                 "FIXTURE_SETSID:incompatible with a fixed rule" "FIXTURE_NEEDS_NET:needs external network" \
                 "FIXTURE_UNATTRIBUTABLE:without an attributable denial"; do
    key="java-${variant%%:*}"
    reason="${variant#*:}"
    rm -rf /var/tmp/layer-prune-counter "${EXERCISES:?}/${key}"
    mkdir -p "${EXERCISES}/${key}"
    cp -r "${EXERCISES}/java/fixture" "${EXERCISES}/${key}/fixture"
    local out
    out="$(prune "${key}" "${WORK}/${key}" "${variant%%:*}=1" 2>&1)"
    local status=$?
    if [[ "${status}" -ne 0 && "${out}" == *"aborted: "*"${reason}"* && ! -e "${WORK}/${key}/${key}_fixture.cfg" ]]; then
      ok "${variant%%:*}=1 aborts with \"${reason}\" and writes no policy"
    else
      bad "${variant%%:*}=1 aborts with \"${reason}\" and writes no policy" "status ${status}: $(tail -3 <<<"${out}")"
    fi
  done
}

set_up
prune java "${OUTPUT}" >"${WORK}/prune.log" 2>&1
status=$?
check "the pruner ends with status 0 on the fixture" "0" "${status}"
[[ "${status}" -eq 0 ]] || sed 's/^/    /' "${WORK}/prune.log" | tail -20
check_permitted
check_forbidden
check_limits_and_containment
check_containment_catches_a_widening
check_merged_and_verified
check_wrong_reasons
finish
