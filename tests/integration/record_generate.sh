#!/usr/bin/env bash
# Holds the recording pruner's generated policy to what it promises, one phase per container.
#
# A session is recorded in one container and replayed in another, and one container cannot start
# another, so record_host.sh starts a new container for each phase and passes its name:
#
#   record     record the generate session (generate.script, a Python REPL that reads, writes, creates,
#              deletes, moves, runs children and uses loopback TCP and UDP), then generate: the gate
#              accepts the policy, its header and rules say what they should, and diff against the
#              shipped Java base lists a missing and an unused row and changes nothing
#   replay     a new container: the generated policy replays the session with no regression, and a copy
#              of it with a [read] of a path that never existed is refused by the parser's gate
#   contain    a new container: under the generated policy, what the session did not touch is refused
#              (canaries in a fine-grained root and outside every recorded directory, a write into a
#              read-only directory, a connection to an unrecorded address, a bind to an unrecorded
#              port) while what it did touch still works
#   second     a new container: a second session that reads a file of a fine-grained root the first did
#              not, recorded into the same recording; generate merges both
#   merged1    a new container: the merged policy replays the first session
#   merged2    a new container: the merged policy replays the second session
#   narrow     a new container: the policy of the first session alone fails the check of the second
#              session, with the missing row as the regression
#   limits     a new container: a sampled batch session and generate --limits write the limits that a
#              batch session allows, and none that it does not
#   limitscheck a new container: the batch session replays under those limits
#
# Runs inside the prune image with tests/ at /tests, var/tmp/helpers at /var/tmp/helpers and core/ at
# /repo-core, all read-only, the fixture exercise at /srv/phobos-record-exercise and a volume shared by
# the phases at /var/tmp/recordings, in an ordinary container: --network none, no --privileged, no
# --cap-add, no --security-opt.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

PHASE="${1:?usage: record_generate.sh record|replay|contain|second|merged1|merged2|narrow|limits|limitscheck}"
RECORDER="${PHOBOS_RECORD:-/var/tmp/helpers/layer_record/phobos-record}"
FIXTURE="${HERE}/record-fixture"
PHOBOS_HOME="${PHOBOS_HOME:-/var/tmp/opt/core}"
RECORDING=/var/tmp/recordings/gen
LIMITED=/var/tmp/recordings/lim
# Inside the recordings, which no listing walks, so the suite's own scratch never makes a container
# look changed.
OUT="$(mktemp -d /var/tmp/recordings/.generate-scratch.XXXXXX)" || { echo "cannot create a working directory" >&2; exit 1; }
# The command of the generate session: Python keeps its history in the working directory, which is
# a path a policy can name, and not in /root, which is too shallow for a write to be granted there.
SESSION=(env HOME=/var/tmp/testing-dir python3 -q)
# The batch session of the limits phases: read the input, write an output, print the marker.
BATCH=(sh -c 'cat input.txt > out.txt; echo "OK-""BATCH"')

# Removes the phase's own scratch directory however the phase ends.
cleanup() {
  rm -rf "${OUT}"
}
trap cleanup EXIT

# Runs the recorder with the given arguments, its output in ${OUT}/<label>.out and its status in
# ${OUT}/<label>.status. Assumes the recorder never reads standard input, which is /dev/null here.
recorder() {
  local label="$1"
  shift
  "${RECORDER}" "$@" < /dev/null > "${OUT}/${label}.out" 2>&1
  printf '%s' "$?" > "${OUT}/${label}.status"
}

# The status a recorder run of the given label ended with.
status_of() {
  cat "${OUT}/$1.status"
}

# A key of the newest check.json of the given recording, printed by Python; a list as its length.
newest_check() {
  python3 - "$1" "$2" <<'PYTHON'
import json
import pathlib
import sys

recording = pathlib.Path(sys.argv[1])
newest = max(recording.glob("check-*"), key=lambda path: int(path.name.removeprefix("check-")))
value = json.loads((newest / "check.json").read_text())[sys.argv[2]]
print(len(value) if isinstance(value, list) else value)
PYTHON
}

# Every regression, new behaviour and reason of the newest check of the given recording, one per line.
newest_findings() {
  python3 - "$1" <<'PYTHON'
import json
import pathlib
import sys

recording = pathlib.Path(sys.argv[1])
newest = max(recording.glob("check-*"), key=lambda path: int(path.name.removeprefix("check-")))
report = json.loads((newest / "check.json").read_text())
for key in ("regressions", "new_behaviour"):
    for entry in report[key]:
        print(key, entry["call"], entry["pairs"])
for reason in report["not_completed"]:
    print("not completed:", reason)
PYTHON
}

# Reports whether the given file holds the given fixed string, with the file's head as detail.
has_line() {
  local title="$1"
  local needle="$2"
  local file="$3"
  if grep -qF -- "${needle}" "${file}"; then
    ok "${title}"
  else
    bad "${title}" "$(head -c 1500 "${file}")"
  fi
}

# Reports that the given file does not hold the given fixed string.
lacks_line() {
  local title="$1"
  local needle="$2"
  local file="$3"
  if grep -qF -- "${needle}" "${file}"; then
    bad "${title}" "$(grep -nF -- "${needle}" "${file}" | head -3)"
  else
    ok "${title}"
  fi
}

# Runs a command under phobos.sh with the generated policy and prints its combined output and its status.
under_policy() {
  "${PHOBOS_HOME}/phobos.sh" --config "${RECORDING}/policy.cfg" -- "$@" 2>&1
  echo "status=$?"
}

# Phase record: the generate session, then generate, then the comparison with a shipped base.
phase_record() {
  recorder record record --name gen --script "${FIXTURE}/generate.script" -- "${SESSION[@]}"
  check "the generate session is recorded with Python's own status" 0 "$(status_of record)"
  recorder generate generate --name gen
  check "generate answers 0: the gate accepts the policy and every call was mapped" 0 "$(status_of generate)"
  if [[ "$(status_of generate)" != 0 ]]; then
    cat "${OUT}/generate.out"
  fi
  local policy="${RECORDING}/policy.cfg"
  has_line "the header says it was recorded and not pruned" "# Recorded by phobos-record, not pruned. Sessions merged: 1" "${policy}"
  has_line "the header says never to record an untrusted submission" "never record an untrusted submission" "${policy}"
  has_line "the loopback server and its client become the loopback wildcard" "allow 127.0.0.1:*" "${policy}"
  has_line "the datagram pair becomes the loopback wildcard for udp" "allow 127.0.0.1:* udp" "${policy}"
  has_line "the kernel's choice of port becomes allow 0" "allow 0" "${policy}"
  has_line "a file of a fine-grained root stays that file" "/etc/hostname" "${policy}"
  lacks_line "the per-session directory is not named by its process id" "cache/" "${policy}"
  lacks_line "the temporary file's random name is not in the policy" "/var/tmp/testing-dir/tmp" "${policy}"
  has_line "the process entries become one per-run grant" "per-run name" "${policy}"
  python3 - "${RECORDING}/record.json" <<'PYTHON'
import json
import sys

record = json.load(open(sys.argv[1]))
assert record["unsupported"] == [], record["unsupported"]
assert record["grants"], "no grant is recorded"
assert all("evidence" in grant for grant in record["grants"])
print("record.json lists", len(record["grants"]), "grants")
PYTHON
  check "record.json is complete and lists the calls behind every grant" 0 "$?"
  local base="/repo-core/config/BaseLanguage-java.cfg"
  local before
  before="$(sha256sum "${base}")"
  recorder diff diff --name gen --policy "${base}"
  check "diff answers 0" 0 "$(status_of diff)"
  has_line "diff names a need the Java base does not grant" "Needed by a session, not granted by the policy:" "${OUT}/diff.out"
  has_line "diff names a row the Java base grants and the session never used" "[create-ipc] /root/.gradle" "${OUT}/diff.out"
  check "diff changed nothing" "${before}" "$(sha256sum "${base}")"
}

# Phase replay: a new container with the recording's starting state.
phase_replay() {
  recorder replay check --name gen --script "${FIXTURE}/generate.script" -- "${SESSION[@]}"
  check "the generated policy replays the session in a fresh container" 0 "$(status_of replay)"
  if [[ "$(status_of replay)" != 0 ]]; then
    newest_findings "${RECORDING}"
    tail -20 "${OUT}/replay.out"
  fi
  check "check.json says fresh-container" fresh-container "$(newest_check "${RECORDING}" mode)"
  check "no regression is found" 0 "$(newest_check "${RECORDING}" regressions)"
  check "the replay ran the session" 0 "$(newest_check "${RECORDING}" not_completed)"
  local spec
  spec="$(mktemp -d /var/tmp/record-gate.XXXXXX)"
  { cat "${RECORDING}/policy.cfg"; printf '\n[read]\n/var/tmp/testing-dir/never-existed\n'; } > "${OUT}/never.cfg"
  "${PHOBOS_HOME}/phobos-policysystem.sh" --spec-dir "${spec}" --config "${OUT}/never.cfg" > "${OUT}/never.out" 2>&1
  check "the parser refuses a [read] of a path that never existed, so the gate would have caught it" 11 "$?"
  rm -rf "${spec}"
}

# Phase contain: what the session did not touch is refused, what it touched still works.
phase_contain() {
  mkdir -p /srv/phobos-record-canary /var/tmp/testing-dir
  cp -a /srv/phobos-record-exercise/. /var/tmp/testing-dir/
  echo secret > /srv/phobos-record-canary/secret
  echo secret > /root/phobos-record-canary
  under_policy cat /root/phobos-record-canary > "${OUT}/canary-root"
  has_line "a canary in a fine-grained root is refused" "Permission denied" "${OUT}/canary-root"
  under_policy cat /srv/phobos-record-canary/secret > "${OUT}/canary-srv"
  has_line "a canary outside every recorded directory is refused" "Permission denied" "${OUT}/canary-srv"
  under_policy sh -c 'echo x > /usr/share/doc/phobos-record-probe' > "${OUT}/doc-write"
  has_line "a write into a directory the session only read is refused" "Permission denied" "${OUT}/doc-write"
  under_policy cat /etc/hostname > "${OUT}/hostname"
  lacks_line "the file the session read is still readable" "Permission denied" "${OUT}/hostname"
  has_line "and its content is printed" "status=0" "${OUT}/hostname"
  under_policy python3 -c 'import socket; socket.create_connection(("10.0.0.1", 80), timeout=2)' > "${OUT}/connect"
  has_line "a connection to an address the session never reached is refused" "Permission denied" "${OUT}/connect"
  under_policy python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 8080))' > "${OUT}/bind"
  has_line "a bind to a port the session never asked for is refused" "Permission denied" "${OUT}/bind"
}

# Phase second: a second session in a container of its own, then generate over both.
phase_second() {
  recorder second record --name gen --script "${FIXTURE}/merge.script" -- "${SESSION[@]}"
  check "the second session is recorded" 0 "$(status_of second)"
  cp "${RECORDING}/policy.cfg" /var/tmp/recordings/gen-first-policy.cfg
  recorder merged generate --name gen
  check "generate over both sessions answers 0" 0 "$(status_of merged)"
  has_line "the merged header counts two sessions" "Sessions merged: 2" "${RECORDING}/policy.cfg"
  has_line "the merged policy holds what only the second session read" "/etc/passwd" "${RECORDING}/policy.cfg"
  has_line "and still what only the first read" "/etc/hostname" "${RECORDING}/policy.cfg"
  lacks_line "the policy of the first session alone lacks /etc/passwd" "/etc/passwd" /var/tmp/recordings/gen-first-policy.cfg
}

# Phase merged1: the merged policy replays the first session.
phase_merged1() {
  recorder merged1 check --name gen --script "${FIXTURE}/generate.script" -- "${SESSION[@]}"
  check "the merged policy replays the first session" 0 "$(status_of merged1)"
  check "no regression is found for the first session" 0 "$(newest_check "${RECORDING}" regressions)"
}

# Phase merged2: the merged policy replays the second session.
phase_merged2() {
  recorder merged2 check --name gen --script "${FIXTURE}/merge.script" -- "${SESSION[@]}"
  check "the merged policy replays the second session" 0 "$(status_of merged2)"
  check "no regression is found for the second session" 0 "$(newest_check "${RECORDING}" regressions)"
}

# Phase narrow: the first session's policy alone fails the second session's check, on the missing row.
phase_narrow() {
  cp /var/tmp/recordings/gen-first-policy.cfg "${RECORDING}/policy.cfg"
  recorder narrow check --name gen --script "${FIXTURE}/merge.script" -- "${SESSION[@]}"
  check "the first session's policy fails the check of the second session" 1 "$(status_of narrow)"
  if newest_findings "${RECORDING}" | grep -q '^regressions .*passwd'; then
    ok "the regression names the refused read of /etc/passwd"
  else
    bad "the regression names the refused read of /etc/passwd" "$(newest_findings "${RECORDING}")"
  fi
}

# Phase limits: a sampled batch session and generate --limits.
phase_limits() {
  recorder batch record --name lim --sample -- "${BATCH[@]}"
  check "the batch session is recorded" 0 "$(status_of batch)"
  recorder limits generate --name lim --limits
  check "generate --limits answers 0" 0 "$(status_of limits)"
  local policy="${LIMITED}/policy.cfg"
  for key in cpu nproc nofile fsize_mb timeout; do
    has_line "a batch session derives ${key}" "${key}=" "${policy}"
  done
  lacks_line "mem_mb is derived only when the program is asserted to pin its address space" "mem_mb=" "${policy}"
  has_line "the header says why mem_mb was not derived" "no mem_mb derived" "${policy}"
}

# Phase limitscheck: the batch session replays under the derived limits.
phase_limitscheck() {
  recorder limitscheck check --name lim -- "${BATCH[@]}"
  check "the batch session replays under its derived limits" 0 "$(status_of limitscheck)"
  check "no regression is found under the limits" 0 "$(newest_check "${LIMITED}" regressions)"
}

case "${PHASE}" in
  record) phase_record ;;
  replay) phase_replay ;;
  contain) phase_contain ;;
  second) phase_second ;;
  merged1) phase_merged1 ;;
  merged2) phase_merged2 ;;
  narrow) phase_narrow ;;
  limits) phase_limits ;;
  limitscheck) phase_limitscheck ;;
  *) bad "known phase" "record, replay, contain, second, merged1, merged2, narrow, limits or limitscheck" "${PHASE}" ;;
esac
finish
