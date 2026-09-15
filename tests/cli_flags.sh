#!/usr/bin/env bash
# The command-line contract of phobos.sh: the renamed restriction flags and their short
# forms, the refusal of an unknown or obsolete option, where the command's own arguments
# begin, and the --allow-unsandboxed debug bypass. None of this needs a Landlock kernel:
# the flags decide which layers assemble, and the bypass runs the command raw. A
# pass-through stand-in for phobos-landlock lets an ordinary run reach the command.
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

# A copy of core with a minimal base policy beside it, so phobos.sh has a sandbox to build,
# and a pass-through stand-in for phobos-landlock so a run reaches the command with no real
# Landlock kernel.
CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
printf '[readonly]\n/usr\n' > "$CORE_X/BaseTest.cfg"
BASE="$CORE_X/BaseTest.cfg"
printf '%s\n' '#!/usr/bin/env bash' \
  'while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done; shift; exec "$@"' > "$WORK/passthrough-landlock"
chmod +x "$WORK/passthrough-landlock"
SPECS="$WORK/specs"
mkdir -p "$SPECS"

# Runs phobos.sh from the copied core, capturing stdout and stderr in OUT and the status in
# RC. The assignment is in this shell, so RC survives, which a command-substitution call
# would not allow.
run_phobos() {
  OUT="$(bash "$CORE_X/phobos.sh" --spec-parent "$1" --landlock-bin "$WORK/passthrough-landlock" "${@:2}" 2>&1)"
  RC=$?
}

echo "== the renamed restriction flags and their short forms run the command =="
run_phobos "$SPECS" --no-runtime-restriction --no-networksystem-restriction \
  --no-resources-restriction --no-filesystem-restriction --config "$BASE" -- /bin/echo flags-ok
if [[ "$RC" -eq 0 && "$OUT" == *"flags-ok"* ]]; then
  ok "the four --no-*-restriction flags run the command"
else
  bad "the four --no-*-restriction flags run the command" "exit 0, flags-ok" "exit ${RC}: $OUT"
fi
run_phobos "$SPECS" -ntr -nnr -nrr -nfr --config "$BASE" -- /bin/echo short-ok
if [[ "$RC" -eq 0 && "$OUT" == *"short-ok"* ]]; then
  ok "the short forms -ntr/-nnr/-nrr/-nfr run the command"
else
  bad "the short forms -ntr/-nnr/-nrr/-nfr run the command" "exit 0, short-ok" "exit ${RC}: $OUT"
fi

# Every layer off still runs through the chain (a filesystem layer with no Landlock), and the
# last layer must remove the specification rather than leak it.
NOLAYERS="$WORK/nolayers"
mkdir -p "$NOLAYERS"
run_phobos "$NOLAYERS" -ntr -nnr -nrr -nfr --config "$BASE" -- /bin/echo cleaned
left="$(find "$NOLAYERS" -mindepth 1 -maxdepth 1 -name 'phobos-spec.*' 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$RC" -eq 0 && "$OUT" == *"cleaned"* && "$left" -eq 0 ]]; then
  ok "a run with every layer disabled leaves no specification behind"
else
  bad "a run with every layer disabled leaves no specification behind" "exit 0, cleaned, no spec left" "exit ${RC}, specs=${left}: $OUT"
fi

echo
echo "== an unknown or obsolete option is refused before anything runs =="
for opt in --no-timeout --no-fs --bogus -x; do
  run_phobos "$SPECS" "$opt" --config "$BASE" -- /bin/echo should-not-run
  if [[ "$RC" -eq 2 && "$OUT" == *"Unknown option: $opt"* && "$OUT" != *"should-not-run"* ]]; then
    ok "refuses '$opt' and runs nothing"
  else
    bad "refuses '$opt' and runs nothing" "exit 2 naming the option, command not run" "exit ${RC}: $OUT"
  fi
done

echo
echo "== the first non-option word starts the command; its own options are not phobos's =="
# The network layer is switched off only to spare these argument-parsing checks its readelf
# dependency; what they test is where the command's own options begin, not the network.
run_phobos "$SPECS" --no-networksystem-restriction --config "$BASE" -- /bin/echo -n after-dashdash
if [[ "$RC" -eq 0 && "$OUT" == *"after-dashdash"* ]]; then
  ok "an option after -- reaches the command"
else
  bad "an option after -- reaches the command" "exit 0, after-dashdash" "exit ${RC}: $OUT"
fi
run_phobos "$SPECS" --no-networksystem-restriction --config "$BASE" /bin/echo -n after-command
if [[ "$RC" -eq 0 && "$OUT" == *"after-command"* ]]; then
  ok "an option after the command word reaches the command"
else
  bad "an option after the command word reaches the command" "exit 0, after-command" "exit ${RC}: $OUT"
fi

echo
echo "== --allow-unsandboxed runs raw even with a base, warns, and leaves no specification =="
RAWSPECS="$WORK/rawspecs"
mkdir -p "$RAWSPECS"
run_phobos "$RAWSPECS" --allow-unsandboxed --config "$BASE" -- /bin/echo raw-ran
disabled=$(grep -c 'DISABLED' <<<"$OUT")
left="$(find "$RAWSPECS" -mindepth 1 -maxdepth 1 -name 'phobos-spec.*' 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$RC" -eq 0 && "$OUT" == *"raw-ran"* && "$OUT" == *"running the command RAW"* \
      && "$disabled" -eq 4 && "$left" -eq 0 ]]; then
  ok "--allow-unsandboxed with a base runs raw, warns, names four disabled layers, leaves no spec"
else
  bad "--allow-unsandboxed with a base runs raw, warns, names four disabled layers, leaves no spec" \
      "exit 0, raw-ran, a RAW warning, four DISABLED lines, no specification left" \
      "exit ${RC}, disabled=${disabled}, specs=${left}: $OUT"
fi

echo
echo "== --no-networksystem-restriction also drops the Landlock TCP-port rules =="
# The kernel-enforced TCP-port rules are built in the filesystem layer, so disabling the
# network restriction must reach it too. A recording stand-in for phobos-landlock captures
# the arguments; a spec naming a concrete external port would produce a --connect-tcp rule.
printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$*" > "$LL_RECORD"; exit 0' > "$WORK/record-landlock"
chmod +x "$WORK/record-landlock"
PORTSPEC="$WORK/portspec"
mkdir -p "$PORTSPEC"
for f in ro.paths rw.paths hide.paths tail.flags; do : > "$PORTSPEC/$f"; done
printf '1.2.3.4 443\n' > "$PORTSPEC/net.rules"

rm -f "$WORK/ll-record"
LL_RECORD="$WORK/ll-record" bash "$CORE_X/phobos-filesystem.sh" \
  --landlock-bin "$WORK/record-landlock" "$PORTSPEC" -- /bin/true >/dev/null 2>&1
with_rules="$(cat "$WORK/ll-record" 2>/dev/null)"
if [[ "$with_rules" == *"--connect-tcp 443"* ]]; then
  ok "with the network restriction on, the concrete port becomes a --connect-tcp rule"
else
  bad "with the network restriction on, the concrete port becomes a --connect-tcp rule" "a --connect-tcp 443 argument" "$with_rules"
fi

rm -f "$WORK/ll-record"
LL_RECORD="$WORK/ll-record" bash "$CORE_X/phobos-filesystem.sh" \
  --landlock-bin "$WORK/record-landlock" --no-network-ports "$PORTSPEC" -- /bin/true >/dev/null 2>&1
without_rules="$(cat "$WORK/ll-record" 2>/dev/null)"
if [[ "$without_rules" != *"--connect-tcp"* ]]; then
  ok "--no-network-ports drops the --connect-tcp rule from Landlock"
else
  bad "--no-network-ports drops the --connect-tcp rule from Landlock" "no --connect-tcp argument" "$without_rules"
fi

echo
printf '%d passed, %d failed\n' "$passed" "$failed"
(( failed == 0 )) || exit 1
