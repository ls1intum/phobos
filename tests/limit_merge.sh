#!/usr/bin/env bash
# The deterministic merge of the timeout and the resource limits across cfgs: the largest
# value wins, a zero disables that limit and wins over any finite value, within one file and
# across files, and the order of the cfgs does not matter. The effective timeout reaches the
# command as PHB_TIMEOUT_SEC and the effective limits as the rlimits it inherits, so a
# pass-through stand-in for phobos-landlock is enough and no Landlock kernel is needed. The
# network layer is switched off only to spare the checks its readelf dependency.
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

CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
printf '%s\n' '#!/usr/bin/env bash' \
  'while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done; shift; exec "$@"' > "$WORK/passthrough-landlock"
chmod +x "$WORK/passthrough-landlock"
SPECS="$WORK/specs"
mkdir -p "$SPECS"

# Runs phobos.sh with the given base body (written beside phobos.sh) and an optional exercise
# body (passed via --config), and prints "<PHB_TIMEOUT_SEC>|<ulimit -v>|<ulimit -n>" as the
# command sees them: the effective timeout and the effective memory and open-file limits.
merge_result() {
  printf '%s\n' "$1" > "$CORE_X/BaseMerge.cfg"
  local cfgargs=()
  if [[ -n "${2:-}" ]]; then
    printf '%s\n' "$2" > "$WORK/ex.cfg"
    cfgargs=(--config "$WORK/ex.cfg")
  fi
  bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" --landlock-bin "$WORK/passthrough-landlock" \
    --no-networksystem-restriction "${cfgargs[@]}" -- \
    bash -c 'printf "%s|%s|%s" "${PHB_TIMEOUT_SEC:-}" "$(ulimit -v)" "$(ulimit -n)"' 2>/dev/null
}
eff_timeout() { merge_result "$1" "${2:-}" | cut -d'|' -f1; }
eff_memkb()   { merge_result "$1" "${2:-}" | cut -d'|' -f2; }
eff_nofile()  { merge_result "$1" "${2:-}" | cut -d'|' -f3; }

echo "== the timeout is the largest any cfg names; a zero disables it and wins =="
check "the larger of two timeouts wins" "5" "$(eff_timeout '[limits]
timeout=5' '[limits]
timeout=2')"
check "a zero disables and wins over a finite timeout" "" "$(eff_timeout '[limits]
timeout=5' '[limits]
timeout=0')"
check "order does not matter: a zero in the base still wins" "" "$(eff_timeout '[limits]
timeout=0' '[limits]
timeout=7')"
check "2 and 2.000 canonicalise to the same spelling" "2" "$(eff_timeout '[limits]
timeout=2.000' '[limits]
timeout=2')"
check "millisecond precision survives when it is the largest" "1.500" "$(eff_timeout '[limits]
timeout=1.500' '[limits]
timeout=1.200')"
check "a zero after a finite value in one file disables it" "" "$(eff_timeout '[limits]
timeout=9
timeout=0' '')"
check "a finite value after a zero in one file stays disabled" "" "$(eff_timeout '[limits]
timeout=0
timeout=9' '')"

echo
echo "== a resource limit follows the same rule, and a zero is not applied =="
check "the larger memory limit wins (256 MB is 262144 KB)" "262144" "$(eff_memkb '[limits]
mem_mb=128' '[limits]
mem_mb=256')"
check "no memory limit leaves it unlimited" "unlimited" "$(eff_memkb '[readonly]
/usr' '')"
check "a memory limit of zero is not applied" "unlimited" "$(eff_memkb '[limits]
mem_mb=256' '[limits]
mem_mb=0')"
check "the larger open-file limit wins" "256" "$(eff_nofile '[limits]
nofile=128' '[limits]
nofile=256')"
n0="$(eff_nofile '[limits]
nofile=256' '[limits]
nofile=0')"
if [[ "$n0" != "256" ]]; then
  ok "an open-file limit of zero is not applied"
else
  bad "an open-file limit of zero is not applied" "the ambient limit, not 256" "$n0"
fi

echo
printf '%d passed, %d failed\n' "$passed" "$failed"
(( failed == 0 )) || exit 1
