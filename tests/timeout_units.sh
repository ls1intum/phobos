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

# Set only once this run has created the legacy wrapper's runtime directory,
# so cleanup can never remove a directory the run found already in place.
WRAPPER_CORE_OWNED=""

cleanup() {
  rm -rf "$WORK"
  if [[ -n "$WRAPPER_CORE_OWNED" ]]; then rm -rf "$WRAPPER_CORE_OWNED"; fi
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
      INI_TMP_DIRS=""
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
accepts "bare value in a timeout section"       '[timeout]
1.234'                                          "1.234"
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

# The legacy wrapper resolves these two through PATH. Shadowing them keeps the
# checks below from running the real sandbox tools on the host.
cp "$WORK/fake-timeout" "$WORK/timeout"
cp "$WORK/fake-landlock" "$WORK/phobos-landlock"

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
  PHB_ENABLE_FILESYSTEM="$enable_fs" \
  PHB_TIMEOUT_SEC="$value" \
  TIMEOUT_BIN="$WORK/fake-timeout" \
  PHOBOS_LANDLOCK_BIN="$WORK/fake-landlock" \
  PHB_TEST_RECORD="$WORK/record" \
    bash "$CORE/phobos-filesystem.sh" "$SPEC" -- /bin/true >/dev/null 2>&1
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

# ---------------------------------------------------------------------
# Legacy wrapper
# ---------------------------------------------------------------------

echo
echo "== legacy wrapper =="

# The wrapper hardcodes its runtime directory, so these checks need that path.
# It truncates allowedList.cfg there, so they only run when the directory does
# not already belong to a real installation.
WRAPPER_CORE=/var/tmp/opt/core
# The plain mkdir is deliberate: it fails rather than succeeding if the
# directory appeared in the meantime, so ownership is never assumed.
if [[ -e "$WRAPPER_CORE" ]]; then
  skip "legacy wrapper timeout contract" \
       "$WRAPPER_CORE already exists; leaving an installed runtime untouched"
elif mkdir -p "$(dirname "$WRAPPER_CORE")" 2>/dev/null &&
     mkdir "$WRAPPER_CORE" 2>/dev/null &&
     WRAPPER_CORE_OWNED="$WRAPPER_CORE" &&
     [[ -w "$WRAPPER_CORE" ]]; then

  # Runs the wrapper over a [limits] body and prints its output followed by an
  # EXIT=<status> line. The wrapper prints the assembled command before it
  # applies the memory limit and exec's, and that printed command is what these
  # checks inspect; the exec itself is not part of this contract.
  run_wrapper() {
    local body=$1
    printf '%s\n' "$body" > "$WORK/base.cfg"
    : > "$WORK/tail.cfg"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$WORK/build.sh"
    chmod +x "$WORK/build.sh"
    local out
    local rc
    out=$(
      cd "$WORK" || exit 1
      PATH="$WORK:$PATH" PHB_TEST_RECORD="$WORK/wrapper-record" \
        bash "$CORE/phobos_wrapper.sh" \
          --base base.cfg --tail tail.cfg -- "$WORK/build.sh" 2>&1
    )
    rc=$?
    printf '%s\nEXIT=%s' "$out" "$rc"
  }

  # Extracts the duration argument that follows --kill-after in the assembled
  # command, or "<none>" when the wrapper never got that far.
  wrapper_timeout_arg() {
    local out
    out=$(run_wrapper "$1")
    if [[ "$out" == *"--kill-after=5s"* ]]; then
      sed -n 's/.*--kill-after=5s \([^ ]*\).*/\1/p' <<<"$out" | head -1
    else
      printf '<none>'
    fi
  }

  check "wrapper: integer seconds"   "2s"     "$(wrapper_timeout_arg '[limits]
timeout=2')"
  check "wrapper: whole seconds"     "2.000s" "$(wrapper_timeout_arg '[limits]
timeout=2.000')"
  check "wrapper: non-whole seconds" "1.234s" "$(wrapper_timeout_arg '[limits]
timeout=1.234')"
  check "wrapper: sub-second"        "0.500s" "$(wrapper_timeout_arg '[limits]
timeout=0.500')"
  check "wrapper: zero disabled"     "0s"     "$(wrapper_timeout_arg '[limits]
timeout=0')"
  check "wrapper: decimal zero"      "0s"     "$(wrapper_timeout_arg '[limits]
timeout=0.000')"
  check "wrapper: absent timeout"    "0s"     "$(wrapper_timeout_arg '[limits]
mem_mb=512')"

  # A section ending on a valid timeout must not abort through the unrelated
  # memory-limit branch.
  check "wrapper: timeout-only section survives" "2.000s" "$(wrapper_timeout_arg '[limits]
timeout=2.000')"
  check "wrapper: timeout as last line after mem_mb" "1.234s" "$(wrapper_timeout_arg '[limits]
mem_mb=512
timeout=1.234')"

  for bad_value in "-1" "+1" "2s" "1e3" ".5" "2.5" "2.00" "2.0000" "1..000" "abc" "2; touch pwned"; do
    out=$(run_wrapper "[limits]
timeout=$bad_value")
    if [[ "$out" == *"invalid timeout"* && "$out" == *"EXIT=1"* && "$out" != *"--kill-after=5s"* ]]; then
      ok "wrapper rejects '$bad_value'"
    else
      bad "wrapper rejects '$bad_value'" "exit 1, an error, and no assembled command" "$out"
    fi
  done

  rm -f "$WORK/pwned-wrapper"
  out=$(run_wrapper "[limits]
timeout=\$(touch $WORK/pwned-wrapper)")
  if [[ "$out" == *"invalid timeout"* && "$out" == *"EXIT=1"* && ! -e "$WORK/pwned-wrapper" ]]; then
    ok "wrapper: command substitution is rejected and not executed"
  else
    bad "wrapper: command substitution is rejected and not executed" \
        "exit 1, an error, and no side effect" "$out"
  fi

else
  skip "legacy wrapper timeout contract" \
       "$WRAPPER_CORE cannot be created on this platform; these checks run on Linux"
fi

# ---------------------------------------------------------------------

echo
printf '%d passed, %d failed, %d skipped\n' "$passed" "$failed" "$skipped"
if (( skipped > 0 )); then
  printf 'Skipped checks did not run and are not counted as passing.\n'
fi
(( failed == 0 )) || exit 1
