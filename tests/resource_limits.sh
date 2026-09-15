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
#
# The values are printed through the ulimit builtin directly, one per line, rather than
# captured with "$(ulimit -u)". RLIMIT_NPROC counts every process the user already runs, not
# just this shell's children, so once apply_resource_limits has set nproc to 32 a command
# substitution forks and fails with EAGAIN on any busy machine (a CI runner among them)
# before it can report a value. A builtin writing to stdout needs no fork. The lines are
# joined into the comma-separated form the check expects by paste, which runs in the outer
# shell where no process limit is in force.
result="$(
  bash -c '
    source "$1/phobos-common.sh"
    apply_resource_limits 64 32 256 10 5
    ulimit -v
    ulimit -u
    ulimit -n
    ulimit -f
    ulimit -t
  ' _ "$CORE" 2>&1 | paste -sd, -
)"
# mem_mb and fsize_mb are given in MB; ulimit -v is KB and ulimit -f is 1024-byte blocks.
check "the memory, process, file, file-size and CPU limits are set" "65536,32,256,10240,5" "$result"

echo
echo "== the resource layer applies the limits from the specification =="
# The layers start one another with exec, so they have to be executable. A checkout does
# not mark them so, the image does, and a copy stands in for the image here.
CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
SPEC="$WORK/spec"
mkdir -p "$SPEC"
for f in ro.paths rw.paths hide.paths tail.flags net.rules; do : > "$SPEC/$f"; done

# Runs the resource layer with the given limits.conf and prints the four soft limits the
# command inherited, comma-separated: memory, open files, file size and CPU time. The command
# prints them through the ulimit builtin, which needs no fork. The layer is a generic wrapper
# now: called at all, it applies the limits and execs the command. Whether it runs at all is
# phobos.sh's decision, exercised by the end-to-end check further down.
#
# nproc is deliberately left out here. It is a per-user limit counting every process the user
# already runs, so a low absolute value strangles the next layer's own start-up fork (its
# HERE="$(...)") on a busy machine such as a CI runner. That the function sets nproc is proven
# by the direct apply check above, which reads it back in the same shell without forking; the
# parsing of every [limits] key, nproc included, is one shared loop, exercised by the four
# keys here.
run_resource_layer() {
  local limits_body=$1
  printf '%s\n' "$limits_body" > "$SPEC/limits.conf"
  bash "$CORE_X/phobos-resources.sh" "$SPEC" -- \
      bash -c 'ulimit -v; ulimit -n; ulimit -f; ulimit -t' 2>&1 | paste -sd, -
}

check "the command inherits every configured limit" "262144,256,10240,5" \
  "$(run_resource_layer 'mem_mb=256
nofile=256
fsize_mb=10
cpu=5')"

echo
echo "== the resource layer refuses a malformed limit rather than running unrestricted =="
# The layer re-validates the specification it reads. A value that is not a whole number must
# fail closed, and must never reach the arithmetic apply_resource_limits performs.
rm -f "$WORK/pwned"
printf 'mem_mb=$(touch %s/pwned)\n' "$WORK" > "$SPEC/limits.conf"
  bash "$CORE_X/phobos-resources.sh" "$SPEC" -- /bin/echo ran >/dev/null 2>&1
rc=$?
if [[ "$rc" -eq 11 && ! -e "$WORK/pwned" ]]; then
  ok "a malformed limit is refused (PHB-EPOLICY) and never evaluated"
else
  bad "a malformed limit is refused (PHB-EPOLICY) and never evaluated" \
      "exit 11 and no side effect" "exit ${rc}, pwned exists: $([[ -e "$WORK/pwned" ]] && echo yes || echo no)"
fi

echo
echo "== the full phobos.sh chain applies and clears the limits =="
# phobos.sh captures the [limits] keys, writes them into the specification, and the resource
# layer applies them. A passthrough stand-in for phobos-landlock lets the command run, and
# --no-networksystem-restriction keeps the preload library out of it.
printf '%s\n' '#!/usr/bin/env bash' \
  'while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done; shift; exec "$@"' > "$WORK/passthrough-landlock"
chmod +x "$WORK/passthrough-landlock"
# A memory limit, not a process limit: nproc is per-user and a low absolute value would
# strangle the sandbox setup's own forks on a busy machine, which is a property of nproc
# rather than of this layer.
printf '[readonly]\n/usr\n[limits]\nmem_mb=256\nnofile=256\n' > "$CORE_X/BaseTest.cfg"
parent="$WORK/specs"
mkdir -p "$parent"
e2e="$(PHOBOS_SPEC_PARENT="$parent" PHOBOS_LANDLOCK_BIN="$WORK/passthrough-landlock" \
  bash "$CORE_X/phobos.sh" --no-networksystem-restriction -- bash -c 'ulimit -v; ulimit -n' 2>/dev/null | paste -sd, -)"
check "a [limits] policy reaches the command through the whole chain" "262144,256" "$e2e"
left="$(find "$parent" -mindepth 1 -maxdepth 1 -name 'phobos-spec.*' 2>/dev/null | wc -l | tr -d ' ')"
check "the run leaves no specification behind" "0" "$left"

e2e_off="$(PHOBOS_SPEC_PARENT="$parent" PHOBOS_LANDLOCK_BIN="$WORK/passthrough-landlock" \
  bash "$CORE_X/phobos.sh" --no-networksystem-restriction --no-resources-restriction -- bash -c 'ulimit -v' 2>/dev/null)"
if [[ "$e2e_off" != "262144" ]]; then
  ok "--no-resources-restriction skips the resource layer end to end"
else
  bad "--no-resources-restriction skips the resource layer end to end" "a memory limit other than 262144" "$e2e_off"
fi

echo
printf '%d passed, %d failed\n' "$passed" "$failed"
(( failed == 0 ))
