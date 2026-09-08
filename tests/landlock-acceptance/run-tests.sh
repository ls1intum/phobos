#!/usr/bin/env bash
# Phobos-on-Landlock acceptance run. Executes inside an ordinary container:
# no --privileged, no --cap-add, no --security-opt.
set -uo pipefail

CORE=/var/tmp/opt/core
TD=/var/tmp/testing-dir
PASS=0
FAIL=0

hdr() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

hdr "0. Umgebung"
echo "  kernel:  $(uname -r) ($(uname -m))"
echo "  landlock ABI: $(phobos-landlock --verbose --rox /usr -- /bin/true 2>&1 | sed -n 's/.*Landlock ABI \([0-9]*\).*/\1/p')"
echo "  caps:    $(grep CapEff /proc/self/status)"

# --- Testdaten ------------------------------------------------------------
mkdir -p "$TD/probe" "$TD/allowed-ro" "$TD/allowed-rw" /var/tmp/secret
echo "public-data" > "$TD/allowed-ro/data.txt"
echo "TOP-SECRET-TESTCASE" > /var/tmp/secret/secret.txt
mkdir -p /root && echo "home-secret" > /root/secret-home.txt

javac -d "$TD/probe" /testsuite/PhobosProbe.java /testsuite/NetServers.java || exit 1
cp /testsuite/BaseLanguage-java.cfg "$CORE/BaseLanguage-java.cfg"

# --- Server ausserhalb der Sandbox ---------------------------------------
java -cp "$TD/probe" NetServers 18080 18081 > /tmp/servers.log 2>&1 &
SRV=$!
for _ in $(seq 1 50); do grep -q servers-ready /tmp/servers.log 2>/dev/null && break; sleep 0.2; done
grep -q servers-ready /tmp/servers.log || { echo "Server kamen nicht hoch"; cat /tmp/servers.log; exit 1; }
echo "  servers: 18080 (erlaubt) + 18081 (verboten) laufen"

# --- Helfer ---------------------------------------------------------------
# probe <erwartet OK|DENIED> <beschreibung> <probe-args...>
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
    bad "$desc -> erwartet $want, bekommen ${got:-<keine RESULT-Zeile>}"
    printf '%s\n' "$out" | sed 's/^/       | /' | tail -6
  fi
}

hdr "1. Dateizugriff, den die Policy NICHT erlaubt (Landlock muss sperren)"
probe DENIED "lesen  /var/tmp/secret/secret.txt"    read  /var/tmp/secret/secret.txt
probe DENIED "schreiben /var/tmp/secret/neu.txt"    write /var/tmp/secret/neu.txt
probe DENIED "lesen  /root/secret-home.txt"         read  /root/secret-home.txt
probe DENIED "schreiben $TD/nope.txt (Baum ist nur lesbar)" write "$TD/nope.txt"

hdr "2. Dateizugriff, den die Policy erlaubt (Landlock darf nicht stoeren)"
probe OK "lesen  $TD/allowed-ro/data.txt"           read  "$TD/allowed-ro/data.txt"
probe OK "schreiben $TD/allowed-rw/out.txt"         write "$TD/allowed-rw/out.txt"

hdr "3. Netzwerk-Endpunkt, den die Policy NICHT erlaubt (libnetblocker muss sperren)"
probe DENIED "connect 127.0.0.1:18081"              connect 127.0.0.1 18081

hdr "4. Netzwerk-Endpunkt, den die Policy erlaubt (libnetblocker darf nicht stoeren)"
probe OK "connect 127.0.0.1:18080"                  connect 127.0.0.1 18080

hdr "5. Timeout (JVM versucht aktiv, ihn per Shutdown-Hook zu blockieren)"
START=$(date +%s)
phobos.sh --config /testsuite/spin-timeout.cfg -- java -cp probe PhobosProbe spin > /tmp/spin.log 2>&1
RC=$?
ELAPSED=$(( $(date +%s) - START ))
echo "  exit=$RC nach ${ELAPSED}s (PHB_ETIMEOUT=14 erwartet)"
sed 's/^/       | /' /tmp/spin.log | head -4
if [[ "$RC" -eq 14 ]]; then
  ok "Timeout hat gegriffen trotz blockierendem Shutdown-Hook"
else
  bad "Timeout: exit $RC statt 14"
fi
if [[ "$ELAPSED" -ge 5 && "$ELAPSED" -le 20 ]]; then
  ok "Beendet nach ${ELAPSED}s (Deadline 5s + kill-after 5s)"
else
  bad "Unplausible Dauer: ${ELAPSED}s"
fi
if pgrep -f "PhobosProbe spin" > /dev/null 2>&1; then
  bad "Prozess laeuft nach dem Timeout weiter"
else
  ok "Kein Restprozess nach dem Timeout"
fi

kill "$SRV" 2>/dev/null
hdr "Ergebnis"
printf '  bestanden: %d, fehlgeschlagen: %d\n\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
