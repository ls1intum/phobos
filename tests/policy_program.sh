#!/usr/bin/env bash
# phobos-policy.sh builds a run's specification from the base and exercise configuration. It
# is the one program that discovers the base policy, parses, merges and writes the spec files,
# and it is callable on its own, so a single layer can be run standalone over a directory it
# fills. No Landlock kernel is needed: this only checks the files it writes and that a layer
# can then be run over them with a pass-through stand-in for phobos-landlock.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="${HERE}/../core"
# shellcheck source=../core/phobos-constants.sh
source "${CORE}/phobos-constants.sh"
WORK="$(mktemp -d)"
export TMPDIR="$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

passed=0
failed=0
ok()  { printf 'ok    %s\n' "$1"; passed=$((passed + 1)); }
bad() { printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"; failed=$((failed + 1)); }
check() { local n=$1 w=$2 g=$3; if [[ "$g" == "$w" ]]; then ok "$n"; else bad "$n" "$w" "$g"; fi; }

CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
printf '[read]\n/usr\n[execute]\n/usr\n[write]\n/tmp\n[create]\n/tmp\n[limits]\nmem_mb=64\n' > "$CORE_X/BaseTest.cfg"

# Makes an empty, owned specification directory the way phobos.sh does, and prints its path.
fresh_spec() {
  local dir
  dir="$(mktemp -d "$WORK/spec.XXXXXX")"
  mkdir -p "$dir/scratch"
  printf '%s' "$dir"
}

echo "== phobos-policy.sh writes the specification files =="
SPEC="$(fresh_spec)"
# The policy is additive: an exercise config adds paths, rights and the larger limit on top
# of the base. Here it only raises a limit; the base paths are all carried through.
printf '[limits]\nmem_mb=128\n' > "$WORK/exercise.cfg"
bash "$CORE_X/phobos-policy.sh" --spec-dir "$SPEC" --config "$WORK/exercise.cfg"
rc=$?
if [[ "$rc" -eq 0 ]]; then ok "a base and an exercise config build a specification"; else bad "a base and an exercise config build a specification" "exit 0" "exit $rc"; fi
check "the base read path is carried through"    "/usr" "$(cat "$SPEC/read.paths")"
check "the base execute path is carried through" "/usr" "$(cat "$SPEC/execute.paths")"
check "the base write path is carried through"   "/tmp" "$(cat "$SPEC/write.paths")"
check "the base create path is carried through"  "/tmp" "$(cat "$SPEC/create.paths")"
check "the largest memory limit wins in the merge" "mem_mb=128" "$(cat "$SPEC/limits.conf")"
check "a path no config named is absent from the spec" "" "$(grep -F /never/granted "$SPEC/read.paths")"

echo
echo "== an exercise adds to the base and cannot remove a base right =="
# Naming a base path in one section only adds; it does not strip the base's other rights on
# that path. Listing /usr in [read] leaves the base's execute right on /usr in place.
NSPEC="$(fresh_spec)"
printf '[read]\n/usr\n' > "$WORK/reaffirm.cfg"
bash "$CORE_X/phobos-policy.sh" --spec-dir "$NSPEC" --config "$WORK/reaffirm.cfg" >/dev/null 2>&1
check "the base read right is kept"                 "/usr" "$(cat "$NSPEC/read.paths")"
check "the base execute right is not removed"       "/usr" "$(cat "$NSPEC/execute.paths")"
# An exercise may grant a right, and name a path, the base did not: the model is additive.
WSPEC="$(fresh_spec)"
printf '[write]\n/usr\n[read]\n/opt/extra\n' > "$WORK/widen.cfg"
out="$(bash "$CORE_X/phobos-policy.sh" --spec-dir "$WSPEC" --config "$WORK/widen.cfg" 2>&1)"
rc=$?
if [[ "$rc" -eq 0 ]]; then ok "an exercise widening the sandbox is accepted (additive model)"; else bad "an exercise widening the sandbox is accepted (additive model)" "exit 0" "exit $rc: $out"; fi
check "the exercise adds write on a base path"      "/usr"       "$(grep -Fx /usr "$WSPEC/write.paths")"
check "the base write path is still present"         "/tmp"       "$(grep -Fx /tmp "$WSPEC/write.paths")"
check "the exercise adds a path the base did not"    "/opt/extra" "$(grep -Fx /opt/extra "$WSPEC/read.paths")"

echo
echo "== phobos-policy.sh refuses when there is no base policy =="
NOBASE="$WORK/nobase"
cp -R "$CORE" "$NOBASE"
chmod +x "$NOBASE"/*.sh
SPEC2="$(fresh_spec)"
out="$(bash "$NOBASE/phobos-policy.sh" --spec-dir "$SPEC2" 2>&1)"
rc=$?
if [[ "$rc" -eq "$PHB_EPOLICY" && "$out" == *"PHB-EPOLICY"* ]]; then
  ok "no Base*.cfg beside the policy program is refused (PHB-EPOLICY)"
else
  bad "no Base*.cfg beside the policy program is refused (PHB-EPOLICY)" "exit ${PHB_EPOLICY} reporting PHB-EPOLICY" "exit $rc: $out"
fi

echo
echo "== a single layer runs standalone over a specification phobos-policy.sh built =="
printf '%s\n' '#!/usr/bin/env bash' \
  'while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done; shift; exec "$@"' > "$WORK/passthrough-landlock"
chmod +x "$WORK/passthrough-landlock"
mem="$(bash "$CORE_X/phobos-resources.sh" "$SPEC" -- bash -c 'ulimit -v' 2>/dev/null)"
check "the resource layer applies the built limit (128 MB is 131072 KB)" "131072" "$mem"

echo
printf '%d passed, %d failed\n' "$passed" "$failed"
(( failed == 0 )) || exit 1
