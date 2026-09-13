#!/usr/bin/env bash
# Tests the resource limits: the [limits] keys are parsed, and applying them sets the
# process's own rlimits. rlimits are self-imposed and need no privilege, exactly as Landlock
# is, which is why they work inside the unprivileged container an exercise runs in. They are
# the in-process line against a fork bomb, a runaway allocation or a file that fills the disk,
# beside the cgroup caps the container is started with.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="${HERE}/../core"
WORK="$(mktemp -d)"
export TMPDIR="$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

passed=0
failed=0
ok()  { printf 'ok    %s\n' "$1"; passed=$((passed + 1)); }
bad() { printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"; failed=$((failed + 1)); }
check() { local n=$1 w=$2 g=$3; if [[ "$g" == "$w" ]]; then ok "$n"; else bad "$n" "$w" "$g"; fi; }

# Parses a [limits] body and prints the five PARSED_LIMIT_* values, comma-separated.
parse_limits() {
  printf '%s\n' "$1" > "$WORK/policy.cfg"
  bash -c '
    source "$1/phobos-common.sh"
    parse_cfg_policy "$2"
    printf "%s,%s,%s,%s,%s" "$PARSED_LIMIT_MEM_MB" "$PARSED_LIMIT_NPROC" \
      "$PARSED_LIMIT_NOFILE" "$PARSED_LIMIT_FSIZE_MB" "$PARSED_LIMIT_CPU"
  ' _ "$CORE" "$WORK/policy.cfg" 2>&1
}

echo "== the [limits] resource keys are parsed =="
check "every resource key is read"  "64,32,256,10,5" "$(parse_limits '[limits]
mem_mb=64
nproc=32
nofile=256
fsize_mb=10
cpu=5')"
check "an absent key stays empty"   "64,,,,"          "$(parse_limits '[limits]
mem_mb=64')"
check "keys and a timeout coexist"  "128,,,,"         "$(parse_limits '[limits]
timeout=2
mem_mb=128')"

echo
echo "== an invalid resource value is a policy error =="
for body in '[limits]
mem_mb=abc' '[limits]
nproc=-1' '[limits]
nofile=1.5'; do
  out="$(parse_limits "$body")"
  rc=$?
  if [[ "$out" == *"PHB-EPOLICY"* ]]; then
    ok "rejects '$(printf '%s' "$body" | tail -1)'"
  else
    bad "rejects '$(printf '%s' "$body" | tail -1)'" "a PHB-EPOLICY report" "rc ${rc}: $out"
  fi
done

echo
echo "== applying the limits sets this process's rlimits =="
# In a subshell, because the ulimit values it sets would otherwise stick for the rest of the
# suite. Each printed value is the soft limit the command tree would inherit.
result="$(
  bash -c '
    source "$1/phobos-common.sh"
    apply_resource_limits 64 32 256 10 5
    printf "%s,%s,%s,%s,%s" "$(ulimit -v)" "$(ulimit -u)" "$(ulimit -n)" "$(ulimit -f)" "$(ulimit -t)"
  ' _ "$CORE" 2>&1
)"
# mem_mb and fsize_mb are given in MB; ulimit -v is KB and ulimit -f is 1024-byte blocks.
check "the memory, process, file, file-size and CPU limits are set" "65536,32,256,10240,5" "$result"

echo
printf '%d passed, %d failed\n' "$passed" "$failed"
(( failed == 0 ))
