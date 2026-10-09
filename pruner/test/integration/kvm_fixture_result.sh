#!/usr/bin/env bash
# Reads what the KVM run produced for the layer pruner's fixture exercise and holds it to both directions.
#
#   kvm_fixture_result.sh <path_sets directory>
#
# The fixture's build binds 127.0.0.1:5000/udp (FIXTURE_UDP=1), which the default prune, on a kernel that
# does not handle Landlock's UDP bind right, never saw refused. The KVM guest's kernel does handle it, so:
#   permitted  the run verified the policy, its cross-check compared a non-empty set of refusals and found
#              no mismatch, and the one thing that differed between the kernels, that UDP bind, became
#              exactly one row, `allow 5000 udp`, in a sidecar whose SHA-256 the record carries;
#   forbidden  no other rule was added, nothing was granted for a refusal the kernel did not name, and the
#              record names the .cfg it verified by its SHA-256, so a changed .cfg is not mistaken for it;
#   merged     the orchestrator writes the row to Abi10-java.cfg and never into the base, which an older
#              kernel would refuse to run under, while a sidecar changed afterwards stops the merge.
# Runs on the host, after the guest, with python3 and the helpers of this repository.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../../protecter/test/harness.sh
source "${HERE}/../../../protecter/test/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
REPO="$(cd -- "${HERE}/../../.." && pwd)"
PATH_SETS="${1:?usage: kvm_fixture_result.sh <path_sets directory>}"
RECORD="${PATH_SETS}/java_fixture.abi10.json"
SIDECAR="${PATH_SETS}/java_fixture.abi10.cfg"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

if [[ ! -f "${RECORD}" ]]; then
  bad "the KVM run wrote its record" "no ${RECORD}"
  finish
fi
summary="$(python3 - "${RECORD}" "${PATH_SETS}/java_fixture.cfg" "${SIDECAR}" <<'PY'
import hashlib
import json
import os
import sys

record = json.load(open(sys.argv[1]))
cfg = open(sys.argv[2], "rb").read()
sidecar = open(sys.argv[3], "rb").read() if os.path.exists(sys.argv[3]) else None
cross = record.get("cross_check", {})
print("verified", record.get("verified"))
print("abi", record.get("landlock_abi"))
print("compared", cross.get("strace_denials", 0) > 0 and cross.get("audit_records", 0) > 0)
print("mismatches", len(record.get("mismatches", [])))
print("rows", [row["rule"] for row in record.get("rows", [])])
print("cfg-hash", record.get("verified_cfg_sha256") == hashlib.sha256(cfg).hexdigest())
print("sidecar-hash", sidecar is not None and record.get("abi10_cfg_sha256") == hashlib.sha256(sidecar).hexdigest())
print("sidecar-rules", sorted(line for line in (sidecar or b"").decode().splitlines() if line and not line.startswith("#")))
PY
)"
check "the KVM run verified the policy on this kernel" "verified True" "$(grep '^verified' <<<"${summary}")"
if [[ "$(grep '^abi' <<<"${summary}" | cut -d' ' -f2)" -ge 10 ]]; then
  ok "the guest kernel offers Landlock version 10 or later"
else
  bad "the guest kernel offers Landlock version 10 or later" "$(grep '^abi' <<<"${summary}")"
fi
check "the cross-check compared refusals strace attributed with records the kernel wrote" "compared True" "$(grep '^compared' <<<"${summary}")"
check "no strace denial lacks an audit record that agrees" "mismatches 0" "$(grep '^mismatches' <<<"${summary}")"
check "exactly one row was added, the UDP bind the kernel refused" "rows ['allow 5000 udp']" "$(grep '^rows' <<<"${summary}")"
check "the sidecar holds that row and nothing else" "sidecar-rules ['[bind]', 'allow 5000 udp']" "$(grep '^sidecar-rules' <<<"${summary}")"
check "the record names the .cfg it verified by its SHA-256" "cfg-hash True" "$(grep '^cfg-hash' <<<"${summary}")"
check "the record names the sidecar by its SHA-256" "sidecar-hash True" "$(grep '^sidecar-hash' <<<"${summary}")"

merge() {
  python3 "${REPO}/pruner/src/orchestrate/orchestrate.py" --langs java --path-dir "$1" --core-dir "$2" \
    --helpers-dir "${REPO}/pruner/src" > "${WORK}/merge.log" 2>&1
}
if merge "${PATH_SETS}" "${WORK}/core" && grep -q '^allow 5000 udp$' "${WORK}/core/Abi10-java.cfg"; then
  ok "the orchestrator writes the row to Abi10-java.cfg"
else
  bad "the orchestrator writes the row to Abi10-java.cfg" "$(tail -3 "${WORK}/merge.log")"
fi
if grep -q 'udp' "${WORK}/core/BaseLanguage-java.cfg"; then
  bad "the base of the language holds no UDP row" "$(grep udp "${WORK}/core/BaseLanguage-java.cfg")"
else
  ok "the base of the language holds no UDP row"
fi
mkdir -p "${WORK}/tampered"
cp "${PATH_SETS}"/java_fixture.* "${WORK}/tampered/"
printf '[bind]\nallow 6000 udp\n' > "${WORK}/tampered/java_fixture.abi10.cfg"
if merge "${WORK}/tampered" "${WORK}/core-tampered"; then
  bad "a sidecar changed after the run stops the merge" "the orchestrator merged it"
elif grep -q 'its SHA-256 differs' "${WORK}/merge.log"; then
  ok "a sidecar changed after the run stops the merge"
else
  bad "a sidecar changed after the run stops the merge" "$(tail -3 "${WORK}/merge.log")"
fi
finish
