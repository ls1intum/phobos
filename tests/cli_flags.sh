#!/usr/bin/env bash
# The command-line contract of phobos.sh: the renamed restriction flags and their short
# forms, the refusal of an unknown or obsolete option, where the command's own arguments
# begin, and the --allow-unsandboxed debug bypass. None of this needs a Landlock kernel:
# the flags decide which layers assemble, and the bypass runs the command raw. A
# pass-through stand-in for phobos-landlock-filesystem-and-networksystem lets an ordinary run reach the command.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harness.sh
source "${HERE}/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../core"
# shellcheck source=../core/phobos-constants.sh
source "${CORE}/phobos-constants.sh"
WORK="$(mktemp -d)"
export TMPDIR="$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# A copy of core with a minimal base policy beside it, so phobos.sh has a sandbox to build,
# and a pass-through stand-in for phobos-landlock-filesystem-and-networksystem so a run reaches the command with no real
# Landlock kernel.
CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
printf '[read]\n/usr\n' > "$CORE_X/BaseTest.cfg"
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
  if [[ "$RC" -eq "$PHB_EXIT_USAGE" && "$OUT" == *"Unknown option: $opt"* && "$OUT" != *"should-not-run"* ]]; then
    ok "refuses '$opt' and runs nothing"
  else
    bad "refuses '$opt' and runs nothing" "exit ${PHB_EXIT_USAGE} naming the option, command not run" "exit ${RC}: $OUT"
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
# The layers a run has, each of which --allow-unsandboxed reports as disabled: the timeout,
# the network, the resource limits and the filesystem.
LAYER_COUNT=4
echo "== --allow-unsandboxed runs raw even with a base, warns, and leaves no specification =="
RAWSPECS="$WORK/rawspecs"
mkdir -p "$RAWSPECS"
run_phobos "$RAWSPECS" --allow-unsandboxed --config "$BASE" -- /bin/echo raw-ran
disabled=$(grep -c 'DISABLED' <<<"$OUT")
left="$(find "$RAWSPECS" -mindepth 1 -maxdepth 1 -name 'phobos-spec.*' 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$RC" -eq 0 && "$OUT" == *"raw-ran"* && "$OUT" == *"running the command RAW"* \
      && "$disabled" -eq "$LAYER_COUNT" && "$left" -eq 0 ]]; then
  ok "--allow-unsandboxed with a base runs raw, warns, names four disabled layers, leaves no spec"
else
  bad "--allow-unsandboxed with a base runs raw, warns, names four disabled layers, leaves no spec" \
      "exit 0, raw-ran, a RAW warning, four DISABLED lines, no specification left" \
      "exit ${RC}, disabled=${disabled}, specs=${left}: $OUT"
fi

echo
echo "== the network layer builds the Landlock TCP-port rules, the filesystem layer does not =="
# The kernel-enforced TCP-port rules moved from the filesystem layer to the network layer, which
# applies them on a network-only Landlock ruleset (--no-filesystem) inside the connect guard's
# child lineage. A recording stand-in for phobos-landlock-filesystem-and-networksystem captures the arguments; a spec naming a
# concrete external port produces a --connect-tcp rule on the network layer's invocation and none
# on the filesystem layer's. The passthrough stand-in stands in for the connect guard: it skips
# its own arguments to the first -- and execs the command tail, which is the network layer's
# phobos-landlock-filesystem-and-networksystem invocation.
printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$*" > "$LL_RECORD"; exit 0' > "$WORK/record-landlock"
chmod +x "$WORK/record-landlock"
PORTSPEC="$WORK/portspec"
mkdir -p "$PORTSPEC"
for f in read.paths execute.paths write.paths create.paths delete.paths tail.flags bind.rules accept.rules; do : > "$PORTSPEC/$f"; done
printf '1.2.3.4 443\n' > "$PORTSPEC/net.rules"

rm -f "$WORK/ll-record"
LL_RECORD="$WORK/ll-record" bash "$CORE_X/phobos-network.sh" \
  --connect-guard-bin "$WORK/passthrough-landlock" --landlock-bin "$WORK/record-landlock" \
  "$PORTSPEC" -- /bin/true >/dev/null 2>&1
net_rules="$(cat "$WORK/ll-record" 2>/dev/null)"
if [[ "$net_rules" == *"--no-filesystem"* && "$net_rules" == *"--connect-tcp 443"* ]]; then
  ok "the network layer puts the concrete port on a --no-filesystem --connect-tcp ruleset"
else
  bad "the network layer puts the concrete port on a --no-filesystem --connect-tcp ruleset" "--no-filesystem with --connect-tcp 443" "$net_rules"
fi

rm -f "$WORK/ll-record"
LL_RECORD="$WORK/ll-record" bash "$CORE_X/phobos-filesystem.sh" \
  --landlock-bin "$WORK/record-landlock" "$PORTSPEC" -- /bin/true >/dev/null 2>&1
fs_rules="$(cat "$WORK/ll-record" 2>/dev/null)"
if [[ "$fs_rules" != *"--connect-tcp"* ]]; then
  ok "the filesystem layer builds no TCP-port rule; ports are the network layer's job"
else
  bad "the filesystem layer builds no TCP-port rule; ports are the network layer's job" "no --connect-tcp argument" "$fs_rules"
fi

echo "== --debug writes its trace to stderr, so the command's own stdout stays clean =="
# The filesystem layer runs the command under the pass-through stand-in, and --debug prints the
# phobos-landlock-filesystem-and-networksystem invocation. That trace must not land on stdout, where it would corrupt output
# a caller captures. stdout must carry only the command's own bytes.
DBG_OUT="$WORK/dbg.out"
DBG_ERR="$WORK/dbg.err"
bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" --landlock-bin "$WORK/passthrough-landlock" \
  --debug -ntr -nnr -nrr --config "$BASE" -- /bin/echo debug-payload > "$DBG_OUT" 2>"$DBG_ERR"
if [[ "$(cat "$DBG_OUT")" == "debug-payload" ]] && grep -q '\[phobos\]' "$DBG_ERR"; then
  ok "the Landlock-path debug trace is on stderr and stdout is only the command output"
else
  bad "the Landlock-path debug trace is on stderr and stdout is only the command output" \
    "stdout 'debug-payload', stderr with [phobos]" "stdout '$(cat "$DBG_OUT")', stderr '$(cat "$DBG_ERR")'"
fi

# The disabled-filesystem path has its own debug block; its trace must be on stderr too.
bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" --landlock-bin "$WORK/passthrough-landlock" \
  --debug -ntr -nnr -nrr -nfr --config "$BASE" -- /bin/echo nofs-payload > "$DBG_OUT" 2>"$DBG_ERR"
if [[ "$(cat "$DBG_OUT")" == "nofs-payload" ]] && grep -q 'filesystem layer disabled' "$DBG_ERR"; then
  ok "the no-Landlock debug trace is on stderr and stdout is only the command output"
else
  bad "the no-Landlock debug trace is on stderr and stdout is only the command output" \
    "stdout 'nofs-payload', stderr with the disabled-layer note" "stdout '$(cat "$DBG_OUT")', stderr '$(cat "$DBG_ERR")'"
fi

echo "== --debug speaks for every layer on stderr and turns on the helpers' verbosity =="
# A base with a timeout and a resource limit, so the timeout and resource layers have work to
# report, and a stand-in for phobos-landlock-filesystem-and-networksystem that records its arguments and then runs the
# command, so the --verbose the filesystem layer hands on can be read back.
DEBUG_CORE="$WORK/core-debug"
cp -R "$CORE" "$DEBUG_CORE"
chmod +x "$DEBUG_CORE"/*.sh
printf '[read]\n/usr\n[limits]\ntimeout = 30\nnofile = 256\n' > "$DEBUG_CORE/BaseTest.cfg"
printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$@" > "$LL_RECORD"' \
  'while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done; shift; exec "$@"' > "$WORK/record-then-run-landlock"
chmod +x "$WORK/record-then-run-landlock"
LL_RECORD="$WORK/ll-debug" bash "$DEBUG_CORE/phobos.sh" --spec-parent "$SPECS" \
  --landlock-bin "$WORK/record-then-run-landlock" --pgroup-lock-bin "$WORK/passthrough-landlock" --debug -nnr -- /bin/echo debug-payload > "$DBG_OUT" 2> "$DBG_ERR"
if [[ "$(cat "$DBG_OUT")" == "debug-payload" ]]; then
  ok "with --debug stdout is still only the command's output"
else
  bad "with --debug stdout is still only the command's output" "debug-payload" "$(cat "$DBG_OUT")"
fi
for layer in phobos policy timeout resources filesystem; do
  if grep -q "^\[phobos\] ${layer}: " "$DBG_ERR"; then
    ok "the ${layer} step reports under --debug"
  else
    bad "the ${layer} step reports under --debug" "a '[phobos] ${layer}:' line on stderr" "$(cat "$DBG_ERR")"
  fi
done
if grep -qx -- '--verbose' "$WORK/ll-debug"; then
  ok "phobos-landlock-filesystem-and-networksystem is handed --verbose under --debug"
else
  bad "phobos-landlock-filesystem-and-networksystem is handed --verbose under --debug" "a --verbose argument" "$(tr '\n' ' ' < "$WORK/ll-debug")"
fi

PHB_DEBUG_ENABLED=1 LL_RECORD="$WORK/ll-env" bash "$DEBUG_CORE/phobos.sh" --spec-parent "$SPECS" \
  --landlock-bin "$WORK/record-then-run-landlock" --pgroup-lock-bin "$WORK/passthrough-landlock" -nnr -- /bin/echo quiet-payload > "$DBG_OUT" 2> "$DBG_ERR"
if ! grep -q '^\[phobos\] ' "$DBG_ERR" && ! grep -qx -- '--verbose' "$WORK/ll-env"; then
  ok "PHB_DEBUG_ENABLED in the environment does not switch debugging on"
else
  bad "PHB_DEBUG_ENABLED in the environment does not switch debugging on" \
    "no debug line and no --verbose" "stderr '$(cat "$DBG_ERR")', landlock '$(tr '\n' ' ' < "$WORK/ll-env")'"
fi

echo "== the exit statuses keep their documented values =="
# The statuses a run ends with are read by whatever grades it, so they are a contract, not a
# detail. Every other suite compares against the names; this is the one place that pins the
# names to the values the documentation promises.
for pair in "PHB_EPOLICY=11" "PHB_ETIMEOUT=14" "PHB_ERUNTIME=15" "PHB_EXIT_USAGE=2" \
            "PHB_ENFORCER_REFUSED_EXIT=125"; do
  constant="${pair%%=*}"
  documented="${pair#*=}"
  if [[ "${!constant}" == "$documented" ]]; then
    ok "${constant} is ${documented}"
  else
    bad "${constant} is ${documented}" "$documented" "${!constant}"
  fi
done

echo "== every PHB_ name a script reads is one a script defines =="
# The lint job follows the source directives, but it deliberately says nothing about a
# variable once a file sources another, so a misspelt PHB_ name is invisible to it. Under
# set -u such a name ends the run at the line that reads it, which may be the refusal path
# of a rarely taken branch. The names are cheap to check here instead. It reads the names a
# script expands, so one used only in an arithmetic context, or set through declare, is
# outside what this covers.
# Assigned anywhere, not only in phobos-constants.sh: PHB_DEBUG_ENABLED is set by phobos-log.sh
# and read across the layers, and the suites set their own PHB_TEST_ names on a fixture.
defined_names="$(grep -rhoE '(^|[^A-Za-z0-9_$])PHB_[A-Z0-9_]+=' "$CORE" "$HERE" --include='*.sh' \
                   | grep -oE 'PHB_[A-Z0-9_]+' | sort -u)"
undefined_names=""
while IFS= read -r used_name; do
  grep -qx -- "$used_name" <<<"$defined_names" || undefined_names+="${used_name} "
done < <(grep -rhoE '\$\{?PHB_[A-Z0-9_]+' "$CORE" "$HERE" --include='*.sh' \
           | sed -E 's/^\$\{?//' | sort -u)
if [[ -z "$undefined_names" ]]; then
  ok "every PHB_ name read by core and the suites is defined"
else
  bad "every PHB_ name read by core and the suites is defined" "no undefined names" "$undefined_names"
fi

echo "== a refusal is written to stderr and leaves stdout to the command =="
# A policy error ends the run before the command starts. Its message is for the person
# reading the log, not part of the output a caller captures from the command.
printf '[bogus]\n/x\n' > "$WORK/bogus.cfg"
bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" --landlock-bin "$WORK/passthrough-landlock" \
  --config "$WORK/bogus.cfg" -- /bin/echo never > "$DBG_OUT" 2> "$DBG_ERR"
if [[ ! -s "$DBG_OUT" ]] && grep -q 'PHB-EPOLICY' "$DBG_ERR"; then
  ok "the PHB-EPOLICY refusal is on stderr and stdout stays empty"
else
  bad "the PHB-EPOLICY refusal is on stderr and stdout stays empty" \
    "empty stdout, PHB-EPOLICY on stderr" "stdout '$(cat "$DBG_OUT")', stderr '$(cat "$DBG_ERR")'"
fi

finish
