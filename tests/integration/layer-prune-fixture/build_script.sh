#!/bin/bash
# The layer pruner's fixture exercise: a build whose tests pass only when the accesses it needs work.
#
# It reads a file it needs, tries an optional one and does without it, reads its own /proc/self/status
# (a per-run name), writes build output, creates a temporary file with a name of its own each run,
# starts a loopback server on a port the kernel chooses and talks to it, tries an external destination
# and does without it, and writes a JUnit report whose test cases record each of those. The variants
# below make it fail for a wrong reason, so the suite can show the pruner aborts instead of granting:
#   FIXTURE_FLAKY=1           readsNeeded fails on every second run (a counter outside the exercise)
#   FIXTURE_NO_SOURCE=1       prints Gradle's NO-SOURCE line and writes no report
#   FIXTURE_SETSID=1          needs setsid, which the timeout's group lock refuses
#   FIXTURE_NEEDS_NET=1       a test passes only when the external attempt is not refused by the sandbox
#   FIXTURE_UNATTRIBUTABLE=1  writesOutput fails once no_new_privs is set, which every layered run sets
#                             and no refused call shows; the external attempt is left out
set -u

NEEDED=/srv/prune-fixture/needed/data.txt
OPTIONAL=/srv/prune-fixture/optional/maybe.txt
REPORT_DIRECTORY=build/test-results/test
COUNTER=/var/tmp/layer-prune-counter

# Prints a testcase element passed when the status given is 0, failed otherwise.
testcase() {
  local name="$1"
  local status="$2"
  if [[ "$status" -eq 0 ]]; then
    printf '  <testcase classname="Fixture" name="%s"/>\n' "$name"
  else
    printf '  <testcase classname="Fixture" name="%s"><failure/></testcase>\n' "$name"
  fi
}

if [[ "${FIXTURE_NO_SOURCE:-0}" == 1 ]]; then
  echo "> Task :compileJava NO-SOURCE"
  exit 0
fi

read_status=1
[[ "$(cat "$NEEDED" 2>/dev/null)" == "needed" ]] && read_status=0
if [[ "${FIXTURE_FLAKY:-0}" == 1 ]]; then
  count="$(cat "$COUNTER" 2>/dev/null || echo 0)"
  echo $(( count + 1 )) > "$COUNTER"
  (( count % 2 == 1 )) && read_status=1
fi

cat "$OPTIONAL" >/dev/null 2>&1

status_status=1
grep -q '^Pid:' /proc/self/status && status_status=0

write_status=1
mkdir -p build/tmp && printf 'out\n' > build/out.txt && [[ "$(cat build/out.txt)" == "out" ]] && write_status=0
printf 'scratch\n' > "build/tmp/${RANDOM}${RANDOM}.tmp" || write_status=1
if [[ "${FIXTURE_UNATTRIBUTABLE:-0}" == 1 ]]; then
  python3 -S -c 'import ctypes, sys; sys.exit(ctypes.CDLL(None).prctl(39, 0, 0, 0, 0))' || write_status=1
fi

server_status=1
coproc SERVER { exec python3 -S -c 'import socket
s = socket.socket()
s.settimeout(5)
s.bind(("127.0.0.1", 0))
s.listen(1)
print(s.getsockname()[1], flush=True)
c, _ = s.accept()
c.sendall(b"pong")
c.close()' 2>&1; }
read -r -t 10 port <&"${SERVER[0]}"
if [[ "${port:-}" =~ ^[0-9]+$ ]] && exec 3<>"/dev/tcp/127.0.0.1/${port}"; then
  reply="$(cat <&3)"
  exec 3<&-
  [[ "$reply" == "pong" ]] && server_status=0
fi
if [[ -n "${SERVER_PID:-}" ]]; then
  kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
fi

external=""
if [[ "${FIXTURE_UNATTRIBUTABLE:-0}" != 1 ]]; then
  external="$( { exec 4<>/dev/tcp/10.0.0.1/80; } 2>&1 )"
fi
external_status=0
if [[ "${FIXTURE_NEEDS_NET:-0}" == 1 && "$external" == *"Permission denied"* ]]; then
  external_status=1
fi

setsid_status=0
if [[ "${FIXTURE_SETSID:-0}" == 1 ]]; then
  setsid true || setsid_status=1
fi

mkdir -p "$REPORT_DIRECTORY"
{
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="Fixture">\n'
  testcase readsNeeded "$read_status"
  testcase readsItsOwnStatus "$status_status"
  testcase writesOutput "$write_status"
  testcase talksToItsServer "$server_status"
  testcase reachesTheNetworkWhenItMust "$external_status"
  testcase startsASession "$setsid_status"
  printf '</testsuite>\n'
} > "${REPORT_DIRECTORY}/TEST-fixture.xml"
exit 0
