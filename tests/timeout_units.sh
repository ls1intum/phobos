#!/usr/bin/env bash
# Regression tests for the timeout contract.
#
# Timeout values are seconds, either whole or with millisecond precision as
# exactly three decimal places. GNU timeout always receives the value with an
# explicit seconds suffix, and a malformed value must abort rather than
# silently leave the command running without a limit.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="${HERE}/../core"

WORK="$(mktemp -d)"
export TMPDIR="$WORK"

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

passed=0
failed=0
skipped=0

ok() {
  printf 'ok    %s\n' "$1"
  passed=$((passed + 1))
}

bad() {
  printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"
  failed=$((failed + 1))
}

skip() {
  printf 'SKIP  %s\n        reason:   %s\n' "$1" "$2"
  skipped=$((skipped + 1))
}

check() {
  local name=$1
  local want=$2
  local got=$3
  if [[ "$got" == "$want" ]]; then ok "$name"; else bad "$name" "$want" "$got"; fi
}

# ---------------------------------------------------------------------
# Modular runtime: configuration parsing
# ---------------------------------------------------------------------

# Parses a policy body and prints "<exit code>|<output>", where the output of a
# successful parse is "value=<PARSED_TIMEOUT>".
run_parser() {
  local body=$1
  printf '%s\n' "$body" > "$WORK/policy.cfg"
  local out
  local rc
  out=$(bash -c '
      source "$1/phobos-common.sh"
      parse_cfg_policy "$2"
      printf "value=%s" "${PARSED_TIMEOUT}"
    ' _ "$CORE" "$WORK/policy.cfg" 2>&1)
  rc=$?
  printf '%s|%s' "$rc" "$out"
}

accepts() {
  local name=$1
  local body=$2
  local want=$3
  check "$name" "0|value=$want" "$(run_parser "$body")"
}

rejects() {
  local name=$1
  local body=$2
  local res
  local rc
  local out
  res=$(run_parser "$body")
  rc=${res%%|*}
  out=${res#*|}
  # PHB_EPOLICY is 11.
  if [[ "$rc" == "11" && "$out" == *"PHB-EPOLICY"* ]]; then
    ok "$name"
  else
    bad "$name" "exit 11 reporting PHB-EPOLICY" "exit $rc: $out"
  fi
}

echo "== modular runtime: accepted timeout values =="
accepts "integer seconds stay supported"        '[limits]
timeout=2'                                      "2"
accepts "larger integer seconds stay supported" '[limits]
timeout=10'                                     "10"
accepts "whole seconds with millisecond digits" '[limits]
timeout=2.000'                                  "2.000"
accepts "non-whole seconds"                     '[limits]
timeout=1.234'                                  "1.234"
accepts "sub-second value survives"             '[limits]
timeout=0.500'                                  "0.500"
accepts "surrounding spaces are not the value"  '[limits]
timeout  =  2.000'                              "2.000"
accepts "zero disables the timeout"             '[limits]
timeout=0'                                      ""
accepts "decimal zero disables the timeout"     '[limits]
timeout=0.000'                                  ""
accepts "absent timeout leaves it disabled"     '[limits]
mem_mb=512'                                     ""
accepts "no limits section at all"              '[readonly]
/usr'                                           ""
accepts "other limit keys are left alone"       '[limits]
mem_mb=512
timeout=2.000'                                  "2.000"
accepts "timeout before another limit key"      '[limits]
timeout=0.500
mem_mb=512'                                     "0.500"

echo
echo "== modular runtime: rejected timeout values =="
rejects "negative"                '[limits]
timeout=-1'
rejects "explicit plus sign"      '[limits]
timeout=+1'
rejects "two numbers"             '[limits]
timeout=1 2'
rejects "unit suffix"             '[limits]
timeout=2s'
rejects "exponent notation"       '[limits]
timeout=1e3'
rejects "missing integer part"    '[limits]
timeout=.5'
rejects "one decimal place"       '[limits]
timeout=2.5'
rejects "two decimal places"      '[limits]
timeout=2.00'
rejects "four decimal places"     '[limits]
timeout=2.0000'
rejects "two decimal points"      '[limits]
timeout=1..000'
rejects "arbitrary text"          '[limits]
timeout=abc'
rejects "empty explicit value"    '[limits]
timeout='
rejects "trailing shell command"  '[limits]
timeout=2; touch pwned'

echo
echo "== modular runtime: configuration content is never executed =="
rm -f "$WORK/pwned"
res=$(run_parser "[limits]
timeout=\$(touch $WORK/pwned)")
rc=${res%%|*}
if [[ "$rc" == "11" && ! -e "$WORK/pwned" ]]; then
  ok "command substitution is rejected and not executed"
else
  bad "command substitution is rejected and not executed" \
      "exit 11 and no side effect" "exit $rc, pwned exists: $([[ -e "$WORK/pwned" ]] && echo yes || echo no)"
fi

# ---------------------------------------------------------------------
# Modular runtime: what GNU timeout actually receives
# ---------------------------------------------------------------------

cat > "$WORK/fake-timeout" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$PHB_TEST_RECORD"
exit 0
FAKE
chmod +x "$WORK/fake-timeout"

cat > "$WORK/fake-landlock" <<'FAKE'
#!/usr/bin/env bash
exit 0
FAKE
chmod +x "$WORK/fake-landlock"

SPEC="$WORK/spec"
mkdir -p "$SPEC"
for f in ro.paths rw.paths hide.paths tail.flags net.rules; do : > "$SPEC/$f"; done

# Runs the filesystem layer and prints its exit status together with the
# duration argument GNU timeout saw, or "<none>" when GNU timeout was not
# invoked at all. The status is part of the assertion so that a layer which
# crashed before invoking GNU timeout cannot look like a disabled timeout.
timeout_arg_for() {
  local enable_fs=$1
  local value=$2
  rm -f "$WORK/record"
  local rc
  local flags=()
  if [[ "$enable_fs" != "1" ]]; then flags+=(--no-landlock); fi
  PHB_TIMEOUT_SEC="$value" \
  TIMEOUT_BIN="$WORK/fake-timeout" \
  PHOBOS_LANDLOCK_BIN="$WORK/fake-landlock" \
  PHB_TEST_RECORD="$WORK/record" \
    bash "$CORE/phobos-filesystem.sh" "${flags[@]}" "$SPEC" -- /bin/true >/dev/null 2>&1
  rc=$?
  if [[ -f "$WORK/record" ]]; then
    printf 'rc=%s arg=%s' "$rc" "$(awk '{print $2}' "$WORK/record")"
  else
    printf 'rc=%s arg=<none>' "$rc"
  fi
}

for layer in 1 0; do
  if [[ "$layer" == "1" ]]; then label="sandboxed path"; else label="direct path"; fi
  echo
  echo "== modular runtime: GNU timeout arguments, $label =="
  check "$label: integer seconds"   "rc=0 arg=2s"     "$(timeout_arg_for "$layer" 2)"
  check "$label: whole seconds"     "rc=0 arg=2.000s" "$(timeout_arg_for "$layer" 2.000)"
  check "$label: non-whole seconds" "rc=0 arg=1.234s" "$(timeout_arg_for "$layer" 1.234)"
  check "$label: sub-second"        "rc=0 arg=0.500s" "$(timeout_arg_for "$layer" 0.500)"
  check "$label: disabled"          "rc=0 arg=<none>" "$(timeout_arg_for "$layer" "")"
done

# The timeout must wrap phobos-landlock directly, so GNU timeout's kill escalation reaches a
# command that ignores SIGTERM (a bash intermediary between them would die on SIGTERM and let
# timeout exit before it escalates). Assert phobos-landlock is the word right after the
# duration in what GNU timeout was invoked with.
echo
echo "== modular runtime: the timeout monitors phobos-landlock directly =="
rm -f "$WORK/record"
PHB_TIMEOUT_SEC="3" \
TIMEOUT_BIN="$WORK/fake-timeout" \
PHOBOS_LANDLOCK_BIN="$WORK/fake-landlock" \
PHB_TEST_RECORD="$WORK/record" \
  bash "$CORE/phobos-filesystem.sh" "$SPEC" -- /bin/true >/dev/null 2>&1
monitored="$(awk '{print $3}' "$WORK/record" 2>/dev/null)"
check "phobos-landlock is timeout's monitored child" "$WORK/fake-landlock" "$monitored"

# ---------------------------------------------------------------------
# Modular parser: [network] host:port splitting
#
# Migrated from the removed legacy-wrapper checks. parse_cfg_policy in
# phobos-common.sh is the single parser the entry point uses; it writes
# "host port" lines into PARSED_NET_FILE. "::1:*" must keep the loopback host
# rather than collapse to an empty host, which the preload library would read
# as allow-all.
# ---------------------------------------------------------------------

echo
echo "== modular parser: [network] host:port grammar =="

# Prints the "host port" lines parse_cfg_policy writes for a [network] body, or nothing when
# the body is refused (a refusal is asserted separately with rejects_net).
parsed_net_rules() {
  bash -c '
    source "$1/phobos-common.sh"
    printf "%s\n" "$2" > "$3/net.cfg"
    parse_cfg_policy "$3/net.cfg" >/dev/null 2>&1
    cat "$PARSED_NET_FILE"
  ' _ "$CORE" "$1" "$WORK"
}

# Asserts parse_cfg_policy refuses a policy body with PHB-EPOLICY.
rejects_net() {
  local name=$1 body=$2 out rc
  printf '%s\n' "$body" > "$WORK/net.cfg"
  out=$(bash -c 'source "$1/phobos-common.sh"; parse_cfg_policy "$2"' _ "$CORE" "$WORK/net.cfg" 2>&1)
  rc=$?
  if [[ "$rc" == "11" && "$out" == *"PHB-EPOLICY"* ]]; then
    ok "$name"
  else
    bad "$name" "exit 11 reporting PHB-EPOLICY" "exit $rc: $out"
  fi
}

check "parser: a bare IPv6 is the whole host, no port"    "::1 *"          "$(parsed_net_rules '[network]
allow ::1')"
check "parser: bracketed IPv6 without a port"             "::1 *"          "$(parsed_net_rules '[network]
allow [::1]')"
check "parser: bracketed IPv6 with a port"                "::1 443"        "$(parsed_net_rules '[network]
allow [::1]:443')"
check "parser: IPv4 with a port"                          "127.0.0.1 8080" "$(parsed_net_rules '[network]
allow 127.0.0.1:8080')"
check "parser: an unbracketed ::1:* is a bogus host"      "::1:* *"        "$(parsed_net_rules '[network]
allow ::1:*')"

rejects_net "a [network] line without allow is refused"    '[network]
localhost'
rejects_net "an IPv6 bracket that never closes is refused" '[network]
allow [::1'
rejects_net "an unknown section is refused"                '[bogus]
/x'
rejects_net "content before any section is refused"        'stray line'
rejects_net "an unknown key in [limits] is refused"        '[limits]
foo=1'
rejects_net "a bare value in a timeout section is refused" '[timeout]
1.234'


# ---------------------------------------------------------------------

echo
printf '%d passed, %d failed, %d skipped\n' "$passed" "$failed" "$skipped"
if (( skipped > 0 )); then
  printf 'Skipped checks did not run and are not counted as passing.\n'
fi
(( failed == 0 )) || exit 1
