#!/usr/bin/env bash
# Phobos-on-Landlock acceptance run. Executes inside an ordinary container:
# no --privileged, no --cap-add, no --security-opt.
set -uo pipefail

CORE=/var/tmp/opt/core
# The image carries the constants beside the scripts under test.
# shellcheck source=/dev/null
source "${CORE}/phobos-constants.sh"
# The loopback ports of the network checks: BaseLanguage-java.cfg beside this suite allows the
# first and not the second, so the two must stay in step with it;
# how often and how far apart the servers' start is awaited; how many lines of a failing
# command's output a failure shows; and the timeout spin-timeout.cfg sets, with the latest a
# run under it may end once the escalation and a loaded runner are allowed for.
ALLOWED_PORT=18080
DENIED_PORT=18081
SERVER_WAIT_ATTEMPTS=50
SERVER_WAIT_SECONDS=0.2
LOG_EXCERPT_LINES=6
SPIN_TIMEOUT_SECONDS=5
SPIN_LATEST_SECONDS=20
TD=/var/tmp/testing-dir
PASS=0
FAIL=0

hdr() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

hdr "0. Environment"
echo "  kernel:  $(uname -r) ($(uname -m))"
# The wrapper names it "Landlock version", which is the same number the kernel calls
# its ABI version. Matching on "Landlock ABI" printed a blank here and nothing asserts
# on this line, so the header quietly stopped reporting the ABI it exists to report.
echo "  landlock ABI: $(phobos-landlock --verbose --rights=rx /usr -- /bin/true 2>&1 | sed -n 's/.*Landlock version \([0-9]*\).*/\1/p')"
echo "  caps:    $(grep CapEff /proc/self/status)"

# --- Test data ------------------------------------------------------------
mkdir -p "$TD/probe" "$TD/allowed-ro" "$TD/allowed-rw" /var/tmp/secret
echo "public-data" > "$TD/allowed-ro/data.txt"
echo "TOP-SECRET-TESTCASE" > /var/tmp/secret/secret.txt
mkdir -p /root && echo "home-secret" > /root/secret-home.txt

javac -d "$TD/probe" /testsuite/PhobosProbe.java /testsuite/NetServers.java || exit 1
cp /testsuite/BaseLanguage-java.cfg "$CORE/BaseLanguage-java.cfg"

# --- Servers outside the sandbox ----------------------------------------
java -cp "$TD/probe" NetServers "$ALLOWED_PORT" "$DENIED_PORT" > /tmp/servers.log 2>&1 &
SRV=$!
for _ in $(seq 1 "$SERVER_WAIT_ATTEMPTS"); do grep -q servers-ready /tmp/servers.log 2>/dev/null && break; sleep "$SERVER_WAIT_SECONDS"; done
grep -q servers-ready /tmp/servers.log || { echo "The servers did not come up"; cat /tmp/servers.log; exit 1; }
echo "  servers: ${ALLOWED_PORT} (allowed) + ${DENIED_PORT} (forbidden) running"

# --- Helpers --------------------------------------------------------------
# probe <expected OK|DENIED> <description> <probe-args...>
probe() {
  local want="$1"; shift
  local desc="$1"; shift
  local out
  out=$(phobos.sh -- java -cp probe PhobosProbe "$@" 2>&1)
  local line
  line=$(printf '%s\n' "$out" | grep '^RESULT ' | head -1)
  local got
  got=$(printf '%s' "$line" | awk '{print $2}')
  if [[ "$got" == "$want" ]]; then
    ok "$desc -> $got"
  else
    bad "$desc -> expected $want, got ${got:-<no RESULT line>}"
    printf '%s\n' "$out" | sed 's/^/       | /' | tail -n "$LOG_EXCERPT_LINES"
  fi
}

hdr "1. File access the policy does NOT allow (Landlock must block it)"
probe DENIED "read   /var/tmp/secret/secret.txt"    read  /var/tmp/secret/secret.txt
probe DENIED "write  /var/tmp/secret/new.txt"      write /var/tmp/secret/new.txt
probe DENIED "read   /root/secret-home.txt"         read  /root/secret-home.txt
probe DENIED "write  $TD/nope.txt (the tree is read-only)" write "$TD/nope.txt"

hdr "2. File access the policy allows (Landlock must not interfere)"
probe OK "read   $TD/allowed-ro/data.txt"           read  "$TD/allowed-ro/data.txt"
probe OK "write  $TD/allowed-rw/out.txt"             write "$TD/allowed-rw/out.txt"

hdr "3. Network endpoint the policy does NOT allow (the connect guard must block it)"
probe DENIED "connect 127.0.0.1:${DENIED_PORT}"       connect 127.0.0.1 "$DENIED_PORT"

hdr "4. Network endpoint the policy allows (neither filter may interfere)"
probe OK "connect 127.0.0.1:${ALLOWED_PORT}"           connect 127.0.0.1 "$ALLOWED_PORT"

hdr "5. Timeout (the JVM actively tries to block it with a shutdown hook)"
START=$(date +%s)
phobos.sh --config /testsuite/spin-timeout.cfg -- java -cp probe PhobosProbe spin > /tmp/spin.log 2>&1
RC=$?
ELAPSED=$(( $(date +%s) - START ))
echo "  exit=$RC after ${ELAPSED}s (PHB_ETIMEOUT=${PHB_ETIMEOUT} expected)"
sed 's/^/       | /' /tmp/spin.log | head -n "$LOG_EXCERPT_LINES"
if [[ "$RC" -eq "$PHB_ETIMEOUT" ]]; then
  ok "The timeout took effect despite the blocking shutdown hook"
else
  bad "Timeout: exit $RC instead of ${PHB_ETIMEOUT}"
fi
if [[ "$ELAPSED" -ge "$SPIN_TIMEOUT_SECONDS" && "$ELAPSED" -le "$SPIN_LATEST_SECONDS" ]]; then
  ok "Ended after ${ELAPSED}s (deadline ${SPIN_TIMEOUT_SECONDS}s + kill-after ${PHB_KILL_AFTER_SECONDS}s)"
else
  bad "Implausible duration: ${ELAPSED}s"
fi
if pgrep -f "PhobosProbe spin" > /dev/null 2>&1; then
  bad "The process is still running after the timeout"
else
  ok "No leftover process after the timeout"
fi

kill "$SRV" 2>/dev/null
hdr "Result"
printf '  passed: %d, failed: %d\n\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
