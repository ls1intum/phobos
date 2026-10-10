#!/usr/bin/env bash
# Proves the virtual sessions and process groups of the supervisors, in both directions.
#
# The testers of Artemis's C GCC and C++ templates start the program with setsid and stop it with
# killpg(getpgid(pid)); SwiftPM starts every child with setpgid(0, 0). Phobos cannot let a process really leave the
# group GNU timeout kills, so the supervisor keeps a ledger and answers these calls from it. This suite runs the
# patterns for real, under phobos.sh, and checks
#   - the program's view: setsid gives it a group of its own (getpgid says so), killpg on that group ends the
#     program and leaves the tester alive, and a child started with posix_spawn and a group of zero is in a group
#     of its own the same way;
#   - the timeout's view: a program that did setsid and keeps running is still ended with the run, so the timeout
#     holds (the very thing a real setsid would have broken);
#   - the refusals: without a supervisor (the timeout layer alone) setsid is still refused, and a join of a
#     group that does not exist, a setsid by a group leader and a setpgid of a process that is not a child fail
#     with the errors Linux gives.
#
# It needs the run-phase image, an ordinary container (no --privileged, no --cap-add, no --security-opt), and
# python3, which every run-phase image but Java carries.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
PROBE_DIR=/var/tmp/groups-probe
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}" "${PROBE_DIR}"' EXIT
if ! command -v python3 >/dev/null 2>&1; then
  skip "the virtual process groups" "python3 is not installed in this image"
  finish
fi
mkdir -p "${PROBE_DIR}" /var/tmp/testing-dir

cat > "${PROBE_DIR}/tester.py" <<'PY'
import os, signal, subprocess, time
child = subprocess.Popen(["sleep", "30"], preexec_fn=os.setsid)
time.sleep(0.5)
group = os.getpgid(child.pid)
print("group_is_pid=%s" % (group == child.pid), flush=True)
print("own_group_kept=%s" % (os.getpgrp() != child.pid), flush=True)
print("session_is_pid=%s" % (os.getsid(child.pid) == child.pid), flush=True)
os.killpg(group, signal.SIGKILL)
child.wait()
print("child_killed=%s" % (child.returncode == -9), flush=True)
print("tester_alive=True", flush=True)
PY
cat > "${PROBE_DIR}/spawn.py" <<'PY'
import os, signal, time
pid = os.posix_spawn("/bin/sleep", ["sleep", "30"], os.environ, setpgroup=0)
time.sleep(0.5)
print("group_is_pid=%s" % (os.getpgid(pid) == pid), flush=True)
os.kill(-pid, signal.SIGKILL)
_, status = os.waitpid(pid, 0)
print("child_killed=%s" % (os.WIFSIGNALED(status) and os.WTERMSIG(status) == 9), flush=True)
print("tester_alive=True", flush=True)
PY
cat > "${PROBE_DIR}/detached.py" <<'PY'
import os, subprocess, time
subprocess.Popen(["sleep", "47"], preexec_fn=os.setsid)
print("started=True", flush=True)
time.sleep(40)
PY
cat > "${PROBE_DIR}/errors.py" <<'PY'
import errno, os, subprocess, time
child = subprocess.Popen(["sleep", "5"], preexec_fn=os.setsid)
time.sleep(0.3)
def attempt(label, call):
    try:
        call()
        print("%s=ok" % label, flush=True)
    except OSError as error:
        print("%s=%s" % (label, errno.errorcode[error.errno]), flush=True)
leader = subprocess.run(["python3", "-c", "import errno, os\nos.setsid()\ntry:\n    os.setsid()\n    print('ok')\nexcept OSError as error:\n    print(errno.errorcode[error.errno])"], capture_output=True, text=True)
print("setsid_again_in_the_group_leader=%s" % leader.stdout.strip(), flush=True)
attempt("setpgid_into_a_group_that_does_not_exist", lambda: os.setpgid(0, 99999))
attempt("setpgid_of_a_process_that_is_not_a_child", lambda: os.setpgid(1, 1))
attempt("setpgid_with_a_negative_group", lambda: os.setpgid(0, -5))
child.kill()
PY
cat > "${PROBE_DIR}/plain.py" <<'PY'
import errno, os, subprocess
try:
    subprocess.Popen(["true"], preexec_fn=os.setsid).wait()
    print("setsid=ok", flush=True)
except Exception as error:
    print("setsid=refused", flush=True)
PY
printf '[read]\n%s\n' "${PROBE_DIR}" > "${WORK}/base.cfg"
printf '[read]\n%s\n[limits]\ntimeout=4\n' "${PROBE_DIR}" > "${WORK}/timed.cfg"

run() {
  local config="$1"
  local script="$2"
  shift 2
  (cd /var/tmp/testing-dir && "${CORE}/phobos.sh" "$@" --config "${config}" -- python3 "${PROBE_DIR}/${script}") 2>"${WORK}/stderr" | tr '\n' ' ' | sed 's/ *$//'
}

echo "== the tester's pattern: setsid, getpgid, killpg =="
check "setsid in the child gives it a group and a session of its own, killpg ends it, the tester lives" \
  "group_is_pid=True own_group_kept=True session_is_pid=True child_killed=True tester_alive=True" "$(run "${WORK}/base.cfg" tester.py)"
echo
echo "== SwiftPM's pattern: posix_spawn with a group of zero =="
check "a child started with setpgroup=0 has a group of its own and kill(-pid) ends it" \
  "group_is_pid=True child_killed=True tester_alive=True" "$(run "${WORK}/base.cfg" spawn.py)"
echo
echo "== the timeout still holds, because the real group never changes =="
began="$(date +%s)"
(cd /var/tmp/testing-dir && "${CORE}/phobos.sh" --config "${WORK}/timed.cfg" -- python3 "${PROBE_DIR}/detached.py" > "${WORK}/detached.out" 2>/dev/null) &
run_pid=$!
for _ in $(seq 1 100); do
  grep -q '^started=True' "${WORK}/detached.out" 2>/dev/null && break
  sleep 0.1
done
check "the program started and did setsid" "started=True" "$(grep -m1 '^started=True' "${WORK}/detached.out")"
sleeper="$(pgrep -f 'sleep 47' | head -1)"
python_pid="$(pgrep -f '^python3 .*detached.py' | head -1)"
if [[ -n "${sleeper}" && -n "${python_pid}" ]] \
    && [[ "$(ps -o pgid= -p "${sleeper}" | tr -d ' ')" == "$(ps -o pgid= -p "${python_pid}" | tr -d ' ')" ]] \
    && [[ "$(ps -o pgid= -p "${sleeper}" | tr -d ' ')" != "${sleeper}" ]]; then
  ok "the process that did setsid is still in the real group of the run, not in one of its own"
else
  bad "the process that did setsid is still in the real group of the run" "sleep 47 pid ${sleeper:-none}, run pid ${python_pid:-none}: $(ps -eo pid,pgid,args | grep -E 'sleep 47|detached' | grep -v grep)"
fi
wait "${run_pid}"
run_status=$?
elapsed=$(( $(date +%s) - began ))
check "the run ends with the timeout's status" "${PHB_ETIMEOUT:-14}" "${run_status}"
if (( elapsed < 20 )); then ok "and within the timeout's grace, not after the program's own 40 seconds (${elapsed} s)"; else bad "the run ends at the timeout" "took ${elapsed} s"; fi
sleep 1
if pgrep -f 'sleep 47' >/dev/null 2>&1; then
  bad "a program that did setsid and keeps running ends with the run at the timeout" "no process 'sleep 47' left" "$(pgrep -af 'sleep 47')"
  pkill -f 'sleep 47' || true
else
  ok "a program that did setsid and keeps running ends with the run at the timeout"
fi
echo
echo "== the errors Linux gives =="
errors="$(run "${WORK}/base.cfg" errors.py)"
check "a group leader cannot start a session again" "EPERM" "$(grep -o 'setsid_again_in_the_group_leader=[A-Za-z]*' <<<"${errors}" | cut -d= -f2)"
check "a group that does not exist cannot be joined" "EPERM" "$(grep -o 'setpgid_into_a_group_that_does_not_exist=[A-Za-z]*' <<<"${errors}" | cut -d= -f2)"
check "a process that is not a child cannot be moved" "ESRCH" "$(grep -o 'setpgid_of_a_process_that_is_not_a_child=[A-Za-z]*' <<<"${errors}" | cut -d= -f2)"
check "a negative group is invalid" "EINVAL" "$(grep -o 'setpgid_with_a_negative_group=[A-Za-z]*' <<<"${errors}" | cut -d= -f2)"
echo
echo "== without a supervisor nothing changes =="
check "with the timeout layer alone, setsid is refused" "setsid=refused" "$(run "${WORK}/timed.cfg" plain.py --no-networksystem-restriction --no-filesystem-restriction)"
check "with a timeout and the filesystem layer alone, it is answered from the ledger" "setsid=ok" "$(run "${WORK}/timed.cfg" plain.py --no-networksystem-restriction)"

finish
