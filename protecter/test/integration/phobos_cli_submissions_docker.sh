#!/usr/bin/env bash
# shellcheck shell=bash
# What phobos-cli.sh submissions does with real containers, on the run-phase image given as $1 and
# the prune image it builds on it: the file only one submission reads exists in the image and the
# shipped bases do not grant it, the fixture's three submissions give two pruned policies and one
# deterministic abort, the row only one submission needs is counted so, the candidate starts the
# layers and is verified against both pruned submissions, a policy without that row does not match
# when verified but starts the layers, and a submission that tries to change its staged exercise, the
# helpers of the pruner or the evidence of its own result changes none of the first two and has its
# run refused at the seal, while its own build output is written.
#
# It needs the docker command and python3, and takes a while, since every submission is pruned and
# verified for real; build.yml runs it on full runs only.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
REPOSITORY="$(cd -- "${HERE}/../../.." && pwd)"
CLI="${REPOSITORY}/phobos-cli.sh"
FIXTURE="${HERE}/submissions-fixture"
IMAGE="${1:?the run-phase image to test is the first argument}"
# shellcheck source=../../src/phobos-tools-common/phobos-constants.sh
source "${REPOSITORY}/protecter/src/phobos-tools-common/phobos-constants.sh"

WORK="$(cd -- "$(mktemp -d)" && pwd -P)"
STATUS=0

# Removes what this suite made: its own directory, the containers' files in it included.
cleanup() {
  docker run --rm -v "${WORK}:/work" --entrypoint /bin/rm "${IMAGE}" -rf /work/case /work/attack > /dev/null 2>&1 || true
  rm -rf -- "${WORK}"
}
trap cleanup EXIT

if ! command -v docker > /dev/null 2>&1 || ! command -v python3 > /dev/null 2>&1; then
  skip "every check with real containers" "docker or python3 is not installed"
  finish
fi
TESTED="$(docker image inspect --format '{{.Id}}' "${IMAGE}")" || { echo "the image ${IMAGE} does not exist" >&2; exit 1; }
if ! docker image inspect phobos-run-phase-java > /dev/null 2>&1; then
  docker tag "${IMAGE}" phobos-run-phase-java || { echo "cannot tag ${IMAGE} as phobos-run-phase-java" >&2; exit 1; }
fi
[[ "$(docker image inspect --format '{{.Id}}' phobos-run-phase-java)" == "${TESTED}" ]] \
  || { echo "phobos-run-phase-java names another image than ${IMAGE}; the suite would test that one" >&2; exit 1; }

# Copies the fixture's template and the submissions folder $2 to the case directory $1, with a
# prune.json naming the key java-gradle and an empty output directory.
prepare() {
  mkdir -p "$1/out"
  cp -R "${FIXTURE}/template" "$1/template"
  cp -R "${FIXTURE}/$2" "$1/submissions"
  printf '{"key": "java-gradle"}\n' > "$1/template/prune.json"
}

# Runs phobos-cli.sh with the words given, keeping its status in STATUS and its error stream in $1.
call() {
  local errors="$1"
  shift
  bash "${CLI}" "$@" < /dev/null > /dev/null 2> "${errors}"
  STATUS=$?
}

echo "== the file only alpha reads"
EXTRA="/etc/os-release"
docker run --rm --network none --entrypoint /bin/cat "${IMAGE}" "${EXTRA}" > /dev/null 2>&1
check "exists in the image and is read without Phobos" 0 "$?"
REAL="$(docker run --rm --network none --entrypoint /usr/bin/realpath "${IMAGE}" "${EXTRA}" 2> /dev/null)"
mkdir -p "${WORK}/empty"
call "${WORK}/control.err" run --image "${IMAGE}" --exercise "${WORK}/empty" -- /bin/true
check "the layers start under the shipped bases alone" 0 "${STATUS}"
call "${WORK}/control.err" run --image "${IMAGE}" --exercise "${WORK}/empty" -- /bin/cat "${EXTRA}"
if [[ "${STATUS}" != 0 ]] && grep -q 'os-release' "${WORK}/control.err"; then ok "and they do not grant it"; else bad "and they do not grant it" "${STATUS} $(cat "${WORK}/control.err")"; fi

echo "== three submissions"
CASE="${WORK}/case"
prepare "${CASE}" submissions
before="$(cd "${CASE}" && find template submissions -type f -exec cksum {} + | sort)"
call "${WORK}/run.err" submissions --template "${CASE}/template" --submissions "${CASE}/submissions" --output "${CASE}/out" --assignment-is-student-code
check "the run ends with 0" 0 "${STATUS}"
RUN="$(find "${CASE}/out" -mindepth 1 -maxdepth 1 -name 'submissions-run.*' | head -1)"
results="$(python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); print(" ".join(e["name"] + "=" + e["result"] for e in sorted(m["submissions"], key=lambda e: e["name"])))' "${RUN}/seal/manifest.json" 2> /dev/null)"
check "two submissions are pruned and the one without a solution is aborted" "alpha=ok beta=ok gamma=aborted" "${results}"
check "on the image given" "${TESTED}" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_phase_image"])' "${RUN}/seal/manifest.json" 2> /dev/null)"
if awk -F '\t' -v link="${EXTRA}" -v real="${REAL}" '$1 == 1 && $2 == 2 && $3 == "read" && (link == $4 || index(link, $4 "/") == 1 || real == $4 || index(real, $4 "/") == 1) { found = 1 } END { exit !found }' "${RUN}/union/rows.tsv" 2> /dev/null; then
  ok "the read of that file is a row only one submission needs, counted so"
else
  bad "the read of that file is a row only one submission needs, counted so" "${REAL} $(cat "${RUN}/union/rows.tsv" 2> /dev/null)"
fi
if cmp -s "${RUN}/union/candidate.cfg" "${RUN}/policy.cfg"; then ok "the candidate is verified and kept as the policy"; else bad "the candidate is verified and kept as the policy" "$(tail -5 "${WORK}/run.err")"; fi
check "the template and the submissions are left as they were" "${before}" "$(cd "${CASE}" && find template submissions -type f -exec cksum {} + | sort)"
python3 - "${RUN}/union/rows.tsv" "${WORK}/edited.cfg" <<'PYTHON'
import sys
rows = [line.rstrip("\n").split("\t") for line in open(sys.argv[1])]
order = ["read", "execute", "write", "create", "delete", "create-ipc", "create-symlink", "restructure", "ioctl", "connect", "bind", "accept", "limits"]
text = ""
for section in order:
    entries = [entry for count, of, kind, entry in rows if kind == section and count == of]
    if entries:
        text += f"[{section}]\n" + "".join(f"{entry}\n" for entry in entries)
open(sys.argv[2], "w").write(text)
PYTHON
call "${WORK}/edited.err" submissions verify --run "${RUN}" --policy "${WORK}/edited.cfg"
check "without the row only one submission needs, the verification fails with 1" 1 "${STATUS}"
call "${WORK}/layers.err" submissions verify --run "${RUN}" --policy "${WORK}/edited.cfg" --layers-only
check "while the layers start under it" 0 "${STATUS}"

echo "== a submission that tries to change what it must not"
ATTACK="${WORK}/attack"
prepare "${ATTACK}" adversarial
template_before="$(cd "${ATTACK}" && find template -type f -exec cksum {} + | sort)"
helpers_before="$(cd "${REPOSITORY}" && find pruner -type f -not -path '*/__pycache__/*' -exec cksum {} + | sort)"
call "${WORK}/attack.err" submissions --template "${ATTACK}/template" --submissions "${ATTACK}/submissions" --output "${ATTACK}/out" --assignment-is-student-code
check "its run is refused" "${PHB_ERUNTIME}" "${STATUS}"
if grep -q 'seal' "${WORK}/attack.err"; then ok "at the seal, which finds what it wrote among its artefacts"; else bad "at the seal, which finds what it wrote among its artefacts" "$(tail -5 "${WORK}/attack.err")"; fi
ATTACK_RUN="$(find "${ATTACK}/out" -mindepth 1 -maxdepth 1 -name 'submissions-run.*' | head -1)"
check "the template is left as it was" "${template_before}" "$(cd "${ATTACK}" && find template -type f -exec cksum {} + | sort)"
check "the helpers of the pruner are left as they were" "${helpers_before}" "$(cd "${REPOSITORY}" && find pruner -type f -not -path '*/__pycache__/*' -exec cksum {} + | sort)"
if [[ -e "${ATTACK_RUN}/staging/delta/submissions/delta/forged" ]]; then bad "its staged exercise is left as it was" "forged"; else ok "its staged exercise is left as it was"; fi
if [[ -e "${ATTACK_RUN}/output/delta/forged" ]]; then ok "its own output directory is the one place it could write"; else bad "its own output directory is the one place it could write" "$(ls -la "${ATTACK_RUN}/output/delta" 2> /dev/null)"; fi

finish
