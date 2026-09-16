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
accepts "no limits section at all"              '[read]
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

SPEC="$WORK/spec"
mkdir -p "$SPEC"
for f in read.paths execute.paths write.paths create.paths delete.paths tail.flags net.rules; do : > "$SPEC/$f"; done

# Runs the timeout layer with a given timeout.sec value and prints its exit status together
# with the duration argument GNU timeout saw, or "<none>" when GNU timeout was not invoked at
# all. The status is part of the assertion so that a layer which crashed before invoking GNU
# timeout cannot look like a disabled timeout.
timeout_arg_for() {
  local value=$1
  rm -f "$WORK/record"
  printf '%s' "$value" > "$SPEC/timeout.sec"
  local rc
  PHB_TEST_RECORD="$WORK/record" \
    bash "$CORE/phobos-timeout.sh" --timeout-bin "$WORK/fake-timeout" "$SPEC" -- /bin/true >/dev/null 2>&1
  rc=$?
  if [[ -f "$WORK/record" ]]; then
    printf 'rc=%s arg=%s' "$rc" "$(awk '{print $2}' "$WORK/record")"
  else
    printf 'rc=%s arg=<none>' "$rc"
  fi
}

echo
echo "== modular runtime: GNU timeout arguments =="
check "integer seconds"   "rc=0 arg=2s"     "$(timeout_arg_for 2)"
check "whole seconds"     "rc=0 arg=2.000s" "$(timeout_arg_for 2.000)"
check "non-whole seconds" "rc=0 arg=1.234s" "$(timeout_arg_for 1.234)"
check "sub-second"        "rc=0 arg=0.500s" "$(timeout_arg_for 0.500)"
check "disabled"          "rc=0 arg=<none>" "$(timeout_arg_for "")"

# GNU timeout must group-kill and escalate: without --foreground it signals the command's whole
# process group, and --kill-after sends SIGKILL after SIGTERM, so a command that ignores SIGTERM
# is still stopped. The layers between the timeout and the command keep themselves alive across
# SIGTERM so that this escalation is what stops such a command; here the invocation that makes
# it possible is asserted.
echo
echo "== modular runtime: the timeout group-kills and escalates =="
rm -f "$WORK/record"
printf '3' > "$SPEC/timeout.sec"
PHB_TEST_RECORD="$WORK/record" \
  bash "$CORE/phobos-timeout.sh" --timeout-bin "$WORK/fake-timeout" "$SPEC" -- /bin/true >/dev/null 2>&1
invocation="$(cat "$WORK/record" 2>/dev/null)"
if [[ "$invocation" == *"--kill-after=5s"* ]]; then
  ok "it escalates to SIGKILL with --kill-after"
else
  bad "it escalates to SIGKILL with --kill-after" "--kill-after=5s in the invocation" "$invocation"
fi
if [[ "$invocation" != *"--foreground"* ]]; then
  ok "it group-kills, without --foreground"
else
  bad "it group-kills, without --foreground" "no --foreground in the invocation" "$invocation"
fi

# ---------------------------------------------------------------------
# Modular parser: [connect] host:port splitting
#
# Migrated from the removed legacy-wrapper checks. parse_cfg_policy in
# phobos-common.sh is the single parser the entry point uses; it writes
# "host port" lines into PARSED_NET_FILE. "::1:*" must keep the loopback host
# rather than collapse to an empty host, which the preload library would read
# as allow-all.
# ---------------------------------------------------------------------

echo
echo "== modular parser: [connect] host:port grammar =="

# Prints the "host port" lines parse_cfg_policy writes for a [connect] body, or nothing when
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

check "parser: a bare IPv6 is the whole host, no port"    "::1 *"          "$(parsed_net_rules '[connect]
allow ::1')"
check "parser: bracketed IPv6 without a port"             "::1 *"          "$(parsed_net_rules '[connect]
allow [::1]')"
check "parser: bracketed IPv6 with a port"                "::1 443"        "$(parsed_net_rules '[connect]
allow [::1]:443')"
check "parser: IPv4 with a port"                          "127.0.0.1 8080" "$(parsed_net_rules '[connect]
allow 127.0.0.1:8080')"
check "parser: an unbracketed ::1:* is a bogus host"      "::1:* *"        "$(parsed_net_rules '[connect]
allow ::1:*')"

rejects_net "a [connect] line without allow is refused"    '[connect]
localhost'
rejects_net "an IPv6 bracket that never closes is refused" '[connect]
allow [::1'
rejects_net "an unknown section is refused"                '[bogus]
/x'
rejects_net "content before any section is refused"        'stray line'
rejects_net "an unknown key in [limits] is refused"        '[limits]
foo=1'
rejects_net "a bare value in a [limits] section is refused" '[limits]
1.234'


# ---------------------------------------------------------------------

echo
printf '%d passed, %d failed, %d skipped\n' "$passed" "$failed" "$skipped"
if (( skipped > 0 )); then
  printf 'Skipped checks did not run and are not counted as passing.\n'
fi
(( failed == 0 )) || exit 1
