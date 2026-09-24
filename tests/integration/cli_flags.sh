#!/usr/bin/env bash
# The command-line contract of phobos.sh: the renamed restriction flags and their short
# forms, the refusal of an unknown or obsolete option, where the command's own arguments
# begin, and the --no-restriction debug bypass. None of this needs a Landlock kernel:
# the flags decide which layers assemble, and the bypass runs the command raw. A
# pass-through stand-in for phobos-landlock-filesystem-and-networksystem lets an ordinary run reach the command.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../core"
# shellcheck source=../../core/phobos-tools-common/phobos-constants.sh
source "${CORE}/phobos-tools-common/phobos-constants.sh"
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
# The same stand-in serves as the timeout's group lock. A default timeout now applies to any
# policy naming none, so the timeout layer is at work in these runs and demands one, and the
# real lock is a C product this suite does not build.
cp "$WORK/passthrough-landlock" "$WORK/passthrough-pgroup-lock"
SPECS="$WORK/specs"
mkdir -p "$SPECS"

# Runs phobos.sh from the copied core, capturing stdout and stderr in OUT and the status in
# RC. The assignment is in this shell, so RC survives, which a command-substitution call
# would not allow.
run_phobos() {
  OUT="$(bash "$CORE_X/phobos.sh" --spec-parent "$1" --landlock-bin "$WORK/passthrough-landlock" --pgroup-lock-bin "$WORK/passthrough-pgroup-lock" "${@:2}" 2>&1)"
  RC=$?
}

echo "== the renamed restriction flags and their short forms run the command =="
run_phobos "$SPECS" --no-timeoutsystem-restriction --no-networksystem-restriction \
  --no-resourcesystem-restriction --no-filesystem-restriction --config "$BASE" -- /bin/echo flags-ok
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
# The three names renamed in the flag rework are in this list deliberately: the break is
# meant to be hard, so an old caller has to fail loudly rather than run under a flag that
# no longer means what it says.
for opt in --no-timeout --no-fs --bogus -x --no-runtime-restriction --no-resources-restriction --allow-unsandboxed; do
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
# The layers a run has, each of which --no-restriction reports as disabled: the timeout,
# the network, the resource limits and the filesystem.
LAYER_COUNT=4
echo "== --no-restriction runs raw even with a base, warns, and leaves no specification =="
RAWSPECS="$WORK/rawspecs"
mkdir -p "$RAWSPECS"
run_phobos "$RAWSPECS" --no-restriction -- /bin/echo raw-ran
disabled=$(grep -c 'DISABLED' <<<"$OUT")
left="$(find "$RAWSPECS" -mindepth 1 -maxdepth 1 -name 'phobos-spec.*' 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$RC" -eq 0 && "$OUT" == *"raw-ran"* && "$OUT" == *"RUNS COMPLETELY UNCONFINED"* \
      && "$disabled" -eq "$LAYER_COUNT" && "$left" -eq 0 ]]; then
  ok "--no-restriction runs raw, warns, names four disabled layers, leaves no spec"
else
  bad "--no-restriction runs raw, warns, names four disabled layers, leaves no spec" \
      "exit 0, raw-ran, an UNCONFINED warning, four DISABLED lines, no specification left" \
      "exit ${RC}, disabled=${disabled}, specs=${left}: $OUT"
fi

# The short form is one character from -nrr, which switches off only the resource limits, so a
# policy beside it is read as the typo it almost certainly is and the run is refused.
run_phobos "$RAWSPECS" -nr --config "$BASE" -- /bin/echo must-not-run
if [[ "$RC" -eq "$PHB_EXIT_USAGE" && "$OUT" != *"must-not-run"* && "$OUT" == *"Did you mean -nrr"* ]]; then
  ok "-nr beside --config is refused rather than run unconfined"
else
  bad "-nr beside --config is refused rather than run unconfined" \
      "exit ${PHB_EXIT_USAGE}, no command output, a message naming -nrr" "exit ${RC}: $OUT"
fi
run_phobos "$RAWSPECS" -nr -- /bin/echo short-raw
if [[ "$RC" -eq 0 && "$OUT" == *"short-raw"* && "$OUT" == *"RUNS COMPLETELY UNCONFINED"* ]]; then
  ok "the short form -nr runs the command raw"
else
  bad "the short form -nr runs the command raw" "exit 0, short-raw, an UNCONFINED warning" "exit ${RC}: $OUT"
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
LL_RECORD="$WORK/ll-record" bash "$CORE_X/phobos-networksystem.sh" \
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

echo
echo "== every script prints its own manual with --help and -h =="
# The manual is the only documentation an operator has inside the image, so each script must
# print one, end successfully and name the flags it actually parses.
for script in phobos phobos-policysystem phobos-filesystem phobos-networksystem phobos-timeoutsystem phobos-resourcesystem; do
  for flag in --help -h; do
    manual="$(bash "$CORE_X/${script}.sh" "$flag" 2>/dev/null)"
    rc=$?
    if [[ "$rc" -eq 0 && "$manual" == *"${script}.sh"* && "$manual" == *"EXIT STATUS"* && "$manual" == *"--help, -h"* ]]; then
      ok "${script}.sh ${flag} prints its manual and ends with 0"
    else
      bad "${script}.sh ${flag} prints its manual and ends with 0" "exit 0 and a manual naming the script" "exit ${rc}: $(printf '%s' "$manual" | head -1)"
    fi
  done
done

# A manual has to name every flag its own parser accepts, or it teaches an operator a surface
# that is smaller than the real one.
for pair in "phobos:--no-timeoutsystem-restriction --no-networksystem-restriction --no-resourcesystem-restriction --no-filesystem-restriction --no-restriction --config --debug --landlock-bin --timeout-bin --pgroup-lock-bin --connect-guard-bin --haproxy-bin --resolver --tail-flags-file --spec-parent" \
            "phobos-policysystem:--spec-dir --tail-flags-file --config --debug" \
            "phobos-filesystem:--no-landlock --landlock-bin --resources-layer --config --spec-parent --tail-flags-file --debug" \
            "phobos-networksystem:--connect-guard-bin --haproxy-bin --resolver --landlock-bin --config --spec-parent --tail-flags-file --debug" \
            "phobos-timeoutsystem:--timeout-bin --pgroup-lock-bin --config --spec-parent --tail-flags-file --debug" \
            "phobos-resourcesystem:--config --spec-parent --tail-flags-file --debug"; do
  script="${pair%%:*}"
  manual="$(bash "$CORE_X/${script}.sh" --help 2>/dev/null)"
  missing=""
  for flag in ${pair#*:}; do
    [[ "$manual" == *"$flag"* ]] || missing="${missing} ${flag}"
  done
  if [[ -z "$missing" ]]; then
    ok "${script}.sh names every flag it parses in its manual"
  else
    bad "${script}.sh names every flag it parses in its manual" "no missing flag" "missing:${missing}"
  fi
done

# A manual that documents a short form the parser does not accept teaches an operator a flag
# that fails. The resource layer is the one that needs no compiled enforcer, so it is where
# this is checked end to end.
short_cfg="$(bash "$CORE_X/phobos-resourcesystem.sh" -c "$BASE" -- /bin/echo short-config-ok 2>&1)"
if [[ "$short_cfg" == *"short-config-ok"* ]]; then
  ok "a layer accepts the -c short form its manual documents"
else
  bad "a layer accepts the -c short form its manual documents" "short-config-ok" "$short_cfg"
fi

echo
echo "== a run given no --config takes its most restrictive shape =="
# Containment: the base policy grants loopback, and a run with no exercise configuration must
# drop it, so the command reaches no network at all.
NETBASE="$WORK/core-net"
cp -R "$CORE" "$NETBASE"
chmod +x "$NETBASE"/*.sh
printf '[read]\n/usr\n[execute]\n/bin\n[connect]\nallow 127.0.0.1:*\n[bind]\nallow 8080\n' > "$NETBASE/BaseTest.cfg"
BARESPECS="$WORK/barespecs"
mkdir -p "$BARESPECS"
BARE_SPEC="$WORK/bare-spec"
mkdir -p "$BARE_SPEC"
bash "$NETBASE/phobos-policysystem.sh" --spec-dir "$BARE_SPEC" 2>/dev/null
if [[ ! -s "$BARE_SPEC/net.rules" && ! -s "$BARE_SPEC/bind.rules" && ! -s "$BARE_SPEC/accept.rules" ]]; then
  ok "no --config drops every [connect], [bind] and [accept] rule the base granted"
else
  bad "no --config drops every [connect], [bind] and [accept] rule the base granted" "three empty rule files" \
    "net '$(tr '\n' ' ' < "$BARE_SPEC/net.rules")', bind '$(tr '\n' ' ' < "$BARE_SPEC/bind.rules")', accept '$(tr '\n' ' ' < "$BARE_SPEC/accept.rules")'"
fi

# Usability, the other direction: the filesystem sections survive, or the command could not
# be executed at all and there would be nothing left to contain.
if [[ -s "$BARE_SPEC/read.paths" ]]; then
  ok "no --config keeps the filesystem the base granted"
else
  bad "no --config keeps the filesystem the base granted" "a non-empty read.paths" "empty"
fi

# The same base with an exercise configuration keeps its network rules, so the drop above is
# the absence of a configuration and not a policy that stopped working.
WITH_SPEC="$WORK/with-spec"
mkdir -p "$WITH_SPEC"
printf '[read]\n/usr\n' > "$WORK/plain.cfg"
bash "$NETBASE/phobos-policysystem.sh" --spec-dir "$WITH_SPEC" --config "$WORK/plain.cfg" 2>/dev/null
if [[ -s "$WITH_SPEC/net.rules" && -s "$WITH_SPEC/bind.rules" ]]; then
  ok "an exercise configuration keeps the base's [connect] and [bind] rules"
else
  bad "an exercise configuration keeps the base's [connect] and [bind] rules" "both rule files non-empty" \
    "net '$(tr '\n' ' ' < "$WITH_SPEC/net.rules")', bind '$(tr '\n' ' ' < "$WITH_SPEC/bind.rules")'"
fi

echo
echo "== a policy naming no timeout or limit falls back to the defaults =="
# Before this, a policy without a [limits] section ran unbounded, and no shipped base carries
# one. The fallback is a floor, never a cap: a larger value and an explicit zero both beat it.
if [[ "$(cat "$BARE_SPEC/timeout.sec")" == "$PHB_DEFAULT_TIMEOUT_SECONDS" ]]; then
  ok "a run no configuration bounded takes the default timeout"
else
  bad "a run no configuration bounded takes the default timeout" "$PHB_DEFAULT_TIMEOUT_SECONDS" "$(cat "$BARE_SPEC/timeout.sec")"
fi
missing_default=""
for pair in "mem_mb=$PHB_DEFAULT_LIMIT_MEM_MB" "nproc=$PHB_DEFAULT_LIMIT_NPROC" "nofile=$PHB_DEFAULT_LIMIT_NOFILE" \
            "fsize_mb=$PHB_DEFAULT_LIMIT_FSIZE_MB" "cpu=$PHB_DEFAULT_LIMIT_CPU"; do
  grep -qx "$pair" "$BARE_SPEC/limits.conf" || missing_default="${missing_default} ${pair}"
done
if [[ -z "$missing_default" ]]; then
  ok "every resource limit no configuration named takes its default"
else
  bad "every resource limit no configuration named takes its default" "every default in limits.conf" "missing:${missing_default}"
fi

# A configuration that names a larger value wins over the default, and one that names zero
# switches that limit off and wins over it too.
LARGER_MEM_MB=$(( PHB_DEFAULT_LIMIT_MEM_MB + 1 ))
OVER_SPEC="$WORK/over-spec"
mkdir -p "$OVER_SPEC"
printf '[limits]\nmem_mb=%s\ntimeout=0\ncpu=0\n' "$LARGER_MEM_MB" > "$WORK/over.cfg"
bash "$NETBASE/phobos-policysystem.sh" --spec-dir "$OVER_SPEC" --config "$WORK/over.cfg" 2>/dev/null
if grep -qx "mem_mb=${LARGER_MEM_MB}" "$OVER_SPEC/limits.conf" && [[ ! -s "$OVER_SPEC/timeout.sec" ]] \
     && ! grep -q '^cpu=' "$OVER_SPEC/limits.conf"; then
  ok "a larger value beats the default and an explicit zero still switches a limit off"
else
  bad "a larger value beats the default and an explicit zero still switches a limit off" \
    "mem_mb=${LARGER_MEM_MB}, an empty timeout.sec, no cpu line" \
    "limits '$(tr '\n' ' ' < "$OVER_SPEC/limits.conf")', timeout '$(cat "$OVER_SPEC/timeout.sec")'"
fi

finish
