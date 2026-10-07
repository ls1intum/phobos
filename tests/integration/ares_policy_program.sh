#!/usr/bin/env bash
# phobos-policysystem.sh given an Ares 2 policy: it is detected by its name, the programming language
# configuration it names selects the base policies and adds its [connect] rows to them, and the policy
# is folded in as an exercise configuration, beside any .cfg, by the same additive merge. Both
# directions are pinned: what the import grants arrives in the specification, and what it must not
# touch, a base row, a row that is only lexically under the base, a .cfg-only run, stays as it was.
# No Landlock kernel is needed: this checks the files the program writes and runs the filesystem
# layer's hierarchy check over them.
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

PROJ="$WORK/proj"
OTHER="$WORK/other"
OUTSIDE="$WORK/outside"
JDK="$WORK/jdk"
mkdir -p "$PROJ/dir" "$OTHER" "$OUTSIDE" "$JDK/lib"
: > "$PROJ/allowed.txt"
: > "$PROJ/x"
: > "$OTHER/x"
: > "$OUTSIDE/data.txt"
ln -s "$OUTSIDE" "$PROJ/link"

# A core of its own, with a language base, a second base and a programming language configuration
# naming only the first. The project tree is the base's [read] and [execute], and the tail flags
# change into it.
CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
printf '[read]\n/usr\n/usr/bin\n%s\n[execute]\n/usr\n/usr/bin\n%s\n[connect]\nallow localhost\n' "$PROJ" "$PROJ" > "$CORE_X/BaseLanguage-test.cfg"
printf '[read]\n%s\n' "$OTHER" > "$CORE_X/BaseOther.cfg"
mkdir -p "$CORE_X/language-configurations"
printf '[base]\nBaseLanguage-test.cfg\n[placeholders]\ntool.home = fixed %s\n[connect]\nallow localhost udp\n' "$JDK" \
  > "$CORE_X/language-configurations/TEST_CONFIGURATION.cfg"
cp "$CORE_X/language-configurations/TEST_CONFIGURATION.cfg" "$CORE_X/language-configurations/SECOND_CONFIGURATION.cfg"
printf '[base]\nBaseLanguage-missing.cfg\n' > "$CORE_X/language-configurations/BROKEN_CONFIGURATION.cfg"
printf -- '--chdir %s\n' "$PROJ" > "$WORK/tail.flags"
printf -- '--chdir %s\n' "$OTHER" > "$WORK/other-tail.flags"
printf -- '--foo\n' > "$WORK/no-chdir.flags"

# Prints an Ares 2 policy with one file system entry for the path given, granting the rights named
# among read, write, create, execute and delete, under the configuration given, which defaults to
# the test one, with a timeout and a network entry when they are given, the entry on the port
# given, 8080 by default.
policy() {
  local path="$1"
  local rights="$2"
  local configuration="${3:-TEST_CONFIGURATION}"
  local timeout="${4:-}"
  local host="${5:-}"
  local port="${6:-8080}"
  local right
  printf 'thisPolicyFileCompliesToThePolicyVersion: 1\nregardingTheSupervisedCode:\n'
  printf '  theFollowingProgrammingLanguageConfigurationIsUsed: %s\n' "$configuration"
  printf '  theFollowingClassesAreTestClasses: []\n  theFollowingResourceAccessesArePermitted:\n'
  printf '    regardingFileSystemInteractions:\n      - onThisPathAndAllPathsBelow: "%s"\n' "$path"
  for right in read overwrite create execute delete; do
    if [[ " $rights " == *" ${right} "* ]]; then
      printf '        %sAllFiles: true\n' "$right"
    else
      printf '        %sAllFiles: false\n' "$right"
    fi
  done
  if [[ -n "$host" ]]; then
    printf '    regardingNetworkConnections:\n      - onTheHost: "%s"\n        onThePort: %s\n' "$host" "$port"
    printf '        openConnections: true\n        sendData: true\n        receiveData: true\n'
  else
    printf '    regardingNetworkConnections: []\n'
  fi
  printf '    regardingCommandExecutions: []\n    regardingThreadCreations: []\n    regardingPackageImports: []\n'
  if [[ -n "$timeout" ]]; then
    printf '    regardingTimeouts:\n      - timeout: %s\n' "$timeout"
  else
    printf '    regardingTimeouts: []\n'
  fi
}

# Makes an empty, owned specification directory the way phobos.sh does, and prints its path.
fresh_spec() {
  local dir
  dir="$(mktemp -d "$WORK/spec.XXXXXX")"
  mkdir -p "$dir/scratch"
  printf '%s' "$dir"
}

# Runs the policy program of the test core over a fresh specification with the arguments given,
# keeping its standard error in ERR and its status in STATUS, and setting SPEC.
run_policy() {
  SPEC="$(fresh_spec)"
  ERR="$(bash "$CORE_X/phobos-policysystem.sh" --spec-dir "$SPEC" "$@" 2>&1 >/dev/null)"
  STATUS=$?
}

# Whether the specification's file of that name holds the line exactly.
spec_has() {
  grep -qxF -- "$2" "$SPEC/$1"
}

echo "== an Ares 2 policy is read and folded in =="
policy allowed.txt read > "$PROJ/allowed.yaml"
run_policy --tail-flags-file "$WORK/tail.flags" --config "$PROJ/allowed.yaml"
check "a policy reading a file under the base's project tree is accepted" "0" "$STATUS"
if spec_has read.paths "$PROJ/allowed.txt"; then bad "the row the base covers is not written" "absent" "present"; else ok "the row the base covers is not written"; fi
if spec_has read.paths "$PROJ"; then ok "the base row that covers it is still there"; else bad "the base row that covers it is still there" "present" "absent"; fi
if [[ "$ERR" == *"already covered by the base policy"* ]]; then ok "and the summary says it is covered by the base"; else bad "and the summary says it is covered by the base" "already covered by the base policy" "$ERR"; fi
if spec_has net.rules "localhost * udp"; then ok "the configuration's [connect] row is in the specification of an Ares run"; else bad "the configuration's [connect] row is in the specification of an Ares run" "localhost * udp" "$(cat "$SPEC/net.rules")"; fi
if spec_has net.rules "localhost *"; then ok "an Ares run keeps the base's network rules, as a run with any --config does"; else bad "an Ares run keeps the base's network rules, as a run with any --config does" "localhost *" "$(cat "$SPEC/net.rules")"; fi
if spec_has read.paths "$OTHER"; then bad "a base the configuration does not name is not folded" "absent" "present"; else ok "a base the configuration does not name is not folded"; fi

policy "$OUTSIDE/data.txt" read > "$WORK/outside.yaml"
run_policy --config "$WORK/outside.yaml"
if spec_has read.paths "$OUTSIDE/data.txt"; then ok "an absolute path outside the base is imported"; else bad "an absolute path outside the base is imported" "present" "$(cat "$SPEC/read.paths")"; fi

policy link/data.txt read > "$WORK/link.yaml"
run_policy --tail-flags-file "$WORK/tail.flags" --config "$WORK/link.yaml"
if [[ "$STATUS" == "$PHB_EPOLICY" && "$ERR" == *"lies inside the project root"* && "$ERR" == *"link.yaml', line 7."* ]]; then ok "a symbolic link inside the project root is refused, with file and line"; else bad "a symbolic link inside the project root is refused, with file and line" "status ${PHB_EPOLICY}" "${STATUS}: ${ERR}"; fi
ln -s "$OUTSIDE" "$WORK/outside-link"
policy "$WORK/outside-link/data.txt" read > "$WORK/outside-link.yaml"
run_policy --tail-flags-file "$WORK/tail.flags" --config "$WORK/outside-link.yaml"
if [[ "$STATUS" == 0 ]] && spec_has read.paths "$WORK/outside-link/data.txt"; then ok "a link outside the project root is allowed and written as written"; else bad "a link outside the project root is allowed and written as written" "status 0" "${STATUS}: ${ERR}"; fi

policy /usr/bin "read execute" > "$WORK/usrbin.yaml"
run_policy --config "$WORK/usrbin.yaml"
if spec_has read.paths /usr/bin && spec_has execute.paths /usr/bin && spec_has read.paths /usr; then ok "a base row an ancestor covers stays as it was beside an import of the same path"; else bad "a base row an ancestor covers stays as it was beside an import of the same path" "/usr and /usr/bin" "$(cat "$SPEC/read.paths")"; fi

policy dir "read create delete" > "$WORK/restructure.yaml"
run_policy --tail-flags-file "$WORK/tail.flags" --config "$WORK/restructure.yaml"
if spec_has create.paths "$PROJ/dir" && spec_has symlink.paths "$PROJ/dir" && spec_has delete.paths "$PROJ/dir" && spec_has refer.paths "$PROJ/dir"; then
  ok "createAllFiles with deleteAllFiles writes create, create-symlink, delete and refer"
else
  bad "createAllFiles with deleteAllFiles writes create, create-symlink, delete and refer" "all four" "$(cat "$SPEC/refer.paths")"
fi

policy '${tool.home}/lib' read > "$WORK/placeholder.yaml"
run_policy --config "$WORK/placeholder.yaml"
if spec_has read.paths "$JDK/lib"; then ok "a placeholder the configuration names resolves to the directory it determines"; else bad "a placeholder the configuration names resolves to the directory it determines" "$JDK/lib" "$(cat "$SPEC/read.paths") $ERR"; fi
policy '${other.home}/lib' read > "$WORK/unnamed.yaml"
run_policy --config "$WORK/unnamed.yaml"
if [[ "$STATUS" == "$PHB_EPOLICY" && "$ERR" == *"is not a placeholder the programming language configuration"* ]]; then ok "a placeholder the configuration does not name is refused"; else bad "a placeholder the configuration does not name is refused" "status ${PHB_EPOLICY}" "${STATUS}: ${ERR}"; fi

policy "$OUTSIDE/data.txt" read "" "" localhost > "$WORK/network.yaml"
run_policy --config "$WORK/network.yaml"
if spec_has net.rules "localhost 8080" && spec_has net.rules "localhost 8080 udp"; then ok "a granted network entry writes a TCP and a UDP rule"; else bad "a granted network entry writes a TCP and a UDP rule" "localhost 8080 and its udp twin" "$(cat "$SPEC/net.rules")"; fi
policy "$OUTSIDE/data.txt" read "" "" 127.0.0.2 0 > "$WORK/loopback-every-port.yaml"
run_policy --config "$WORK/loopback-every-port.yaml"
if [[ "$STATUS" == 0 ]] && spec_has net.rules "127.0.0.2 *" && spec_has net.rules "127.0.0.2 * udp"; then ok "a loopback address with port 0 becomes every port of it, over TCP and UDP"; else bad "a loopback address with port 0 becomes every port of it, over TCP and UDP" "status 0" "${STATUS}: $(cat "$SPEC/net.rules" 2>&1) ${ERR}"; fi
for host in 10.0.0.1 2001:db8::1; do
  policy "$OUTSIDE/data.txt" read "" "" "$host" 0 > "$WORK/far-every-port.yaml"
  run_policy --config "$WORK/far-every-port.yaml"
  if [[ "$STATUS" == "$PHB_EPOLICY" && "$ERR" == *"other than loopback; name the port"* && "$ERR" == *"far-every-port.yaml', line 14."* ]]; then ok "${host} with port 0 is refused at its line"; else bad "${host} with port 0 is refused at its line" "status ${PHB_EPOLICY}" "${STATUS}: ${ERR}"; fi
done

echo
echo "== an Ares policy means what the hand-written .cfg of the same meaning means =="
CORE_E="$WORK/core-e"
cp -R "$CORE_X" "$CORE_E"
rm -f "$CORE_E/BaseOther.cfg"
policy "$OUTSIDE/data.txt" "read overwrite" "" 5000 localhost > "$WORK/meaning.yaml"
printf '[read]\n%s\n[write]\n%s\n[connect]\nallow localhost udp\nallow localhost:8080\nallow localhost:8080 udp\n[limits]\ntimeout=5.000\n' \
  "$OUTSIDE/data.txt" "$OUTSIDE/data.txt" > "$WORK/meaning.cfg"
ares_spec="$(fresh_spec)"
bash "$CORE_E/phobos-policysystem.sh" --spec-dir "$ares_spec" --tail-flags-file "$WORK/tail.flags" --config "$WORK/meaning.yaml" 2>/dev/null
ares_status=$?
cfg_spec="$(fresh_spec)"
bash "$CORE_E/phobos-policysystem.sh" --spec-dir "$cfg_spec" --tail-flags-file "$WORK/tail.flags" --config "$WORK/meaning.cfg" 2>/dev/null
cfg_status=$?
difference="$(diff -r -x scratch "$ares_spec" "$cfg_spec" 2>&1)"
if (( ares_status == 0 && cfg_status == 0 )) && grep -qxF "$OUTSIDE/data.txt" "$ares_spec/read.paths" \
  && grep -qxF "localhost 8080 udp" "$ares_spec/net.rules" && [[ -z "$difference" ]]; then
  ok "the specification of the Ares policy equals that of the .cfg, the configuration's [connect] row written into the .cfg"
else
  bad "the specification of the Ares policy equals that of the .cfg, the configuration's [connect] row written into the .cfg" \
    "both built, holding the grant, and no difference" "statuses ${ares_status} and ${cfg_status}: ${difference}"
fi

echo
echo "== base selection =="
printf '[read]\n%s\n' "$OUTSIDE" > "$WORK/plain.cfg"
run_policy --config "$WORK/plain.cfg"
if spec_has read.paths "$OTHER" && spec_has read.paths "$PROJ"; then ok "a run without an Ares policy still folds every Base*.cfg"; else bad "a run without an Ares policy still folds every Base*.cfg" "both bases" "$(cat "$SPEC/read.paths")"; fi
if [[ "$STATUS" == 0 && -f "$SPEC/net.rules" ]] && ! grep -q ' udp$' "$SPEC/net.rules"; then ok "a run without an Ares policy holds no UDP row, since no configuration was loaded"; else bad "a run without an Ares policy holds no UDP row, since no configuration was loaded" "status 0 and no udp row" "${STATUS}: $(cat "$SPEC/net.rules" 2>&1)"; fi
policy allowed.txt read BROKEN_CONFIGURATION > "$WORK/broken.yaml"
run_policy --tail-flags-file "$WORK/tail.flags" --config "$WORK/broken.yaml"
if [[ "$STATUS" == "$PHB_EPOLICY" && "$ERR" == *"'BaseLanguage-missing.cfg' named in [base] does not exist"* ]]; then ok "a configuration naming a base that does not exist is refused, naming it"; else bad "a configuration naming a base that does not exist is refused, naming it" "status ${PHB_EPOLICY}" "${STATUS}: ${ERR}"; fi
policy allowed.txt read NO_SUCH_CONFIGURATION > "$WORK/nofile.yaml"
run_policy --tail-flags-file "$WORK/tail.flags" --config "$WORK/nofile.yaml"
if [[ "$STATUS" == "$PHB_EPOLICY" && "$ERR" == *"has no file 'language-configurations/NO_SUCH_CONFIGURATION.cfg'"* ]]; then ok "a configuration with no file is refused"; else bad "a configuration with no file is refused" "status ${PHB_EPOLICY}" "${STATUS}: ${ERR}"; fi
policy allowed.txt read SECOND_CONFIGURATION > "$WORK/second.yaml"
run_policy --tail-flags-file "$WORK/tail.flags" --config "$PROJ/allowed.yaml" --config "$WORK/second.yaml"
if [[ "$STATUS" == "$PHB_EPOLICY" && "$ERR" == *"one run has one base and one set of placeholder values"* ]]; then ok "two policies naming different configurations are refused, though both name the same base"; else bad "two policies naming different configurations are refused, though both name the same base" "status ${PHB_EPOLICY}" "${STATUS}: ${ERR}"; fi

echo
echo "== an Ares policy beside a .cfg =="
policy "$OUTSIDE/data.txt" read "" 5000 > "$WORK/merge.yaml"
printf '[read]\n%s/x\n[limits]\ntimeout=7\n' "$OTHER" > "$WORK/merge.cfg"
run_policy --tail-flags-file "$WORK/tail.flags" --config "$WORK/merge.yaml" --config "$WORK/merge.cfg"
first="$SPEC"
run_policy --tail-flags-file "$WORK/tail.flags" --config "$WORK/merge.cfg" --config "$WORK/merge.yaml"
second="$SPEC"
check "the specification is the same in either order" "" "$(diff -r -x scratch "$first" "$second" 2>&1)"
if grep -qxF "$OUTSIDE/data.txt" "$first/read.paths" && grep -qxF "$OTHER/x" "$first/read.paths"; then ok "the paths of both are unioned"; else bad "the paths of both are unioned" "both" "$(cat "$first/read.paths")"; fi
check "the largest timeout across files wins" "7" "$(cat "$first/timeout.sec")"
policy "$OUTSIDE/data.txt" read "" 9000 > "$WORK/merge.yaml"
run_policy --config "$WORK/merge.yaml" --config "$WORK/merge.cfg"
check "a larger Ares timeout wins over a smaller .cfg one" "9" "$(cat "$SPEC/timeout.sec")"

printf '[read]\n%s/allowed.txt\n' "$PROJ" > "$WORK/narrow.cfg"
run_policy --tail-flags-file "$WORK/tail.flags" --config "$PROJ/allowed.yaml" --config "$WORK/narrow.cfg"
hierarchy="$(
  export PHOBOS_SCRATCH="$WORK/scratch-hierarchy"
  mkdir -p "$PHOBOS_SCRATCH"
  # shellcheck source=../../core/phobos-tools-common/phobos-common.sh
  source "${CORE}/phobos-tools-common/phobos-common.sh"
  args=()
  build_path_args args "$SPEC/read.paths" "$SPEC/execute.paths" "$SPEC/write.paths" "$SPEC/create.paths" \
    "$SPEC/delete.paths" "$SPEC/ipc.paths" "$SPEC/symlink.paths" "$SPEC/refer.paths" 2>&1 >/dev/null
  printf '%s' "${args[*]}" > /dev/null
)"
hierarchy_status=$?
if (( hierarchy_status == PHB_EPOLICY )) && [[ "$hierarchy" == *"Policy unenforceable"* ]]; then ok "a strict-subset .cfg row beside an Ares policy is still refused by the hierarchy check"; else bad "a strict-subset .cfg row beside an Ares policy is still refused by the hierarchy check" "status ${PHB_EPOLICY}" "${hierarchy_status}: ${hierarchy}"; fi
for case in "$PROJ/allowed.yaml|$PROJ" "$WORK/outside-link.yaml|$WORK/outside-link/data.txt"; do
  yaml="${case%|*}"
  run_policy --tail-flags-file "$WORK/tail.flags" --config "$yaml"
  built="$STATUS"
  spec_has read.paths "${case#*|}" || built="no read row ${case#*|}"
  hierarchy="$(
    export PHOBOS_SCRATCH="$WORK/scratch-hierarchy"
    mkdir -p "$PHOBOS_SCRATCH"
    # shellcheck source=../../core/phobos-tools-common/phobos-common.sh
    source "${CORE}/phobos-tools-common/phobos-common.sh"
    args=()
    build_path_args args "$SPEC/read.paths" "$SPEC/execute.paths" "$SPEC/write.paths" "$SPEC/create.paths" \
      "$SPEC/delete.paths" "$SPEC/ipc.paths" "$SPEC/symlink.paths" "$SPEC/refer.paths" 2>&1 >/dev/null
    printf '%s' "${args[*]}" > /dev/null
  )"
  hierarchy_status=$?
  if [[ "$built" == 0 ]] && (( hierarchy_status == 0 )); then ok "the specification of ${yaml##*/} alone is built and passes the hierarchy check"; else bad "the specification of ${yaml##*/} alone is built and passes the hierarchy check" "status 0 twice" "${built}, ${hierarchy_status}: ${hierarchy}"; fi
done

echo
echo "== the project root =="
# A right the base does not grant on the project tree, so the row is not left out as covered.
policy x overwrite > "$WORK/relative.yaml"
run_policy --tail-flags-file "$WORK/tail.flags" --config "$WORK/relative.yaml"
if spec_has write.paths "$PROJ/x"; then ok "a relative path resolves against the tail's last --chdir"; else bad "a relative path resolves against the tail's last --chdir" "$PROJ/x" "$(cat "$SPEC/write.paths") $ERR"; fi
run_policy --tail-flags-file "$WORK/other-tail.flags" --config "$WORK/relative.yaml"
if spec_has write.paths "$OTHER/x"; then ok "another tail's --chdir gives another path for the same policy"; else bad "another tail's --chdir gives another path for the same policy" "$OTHER/x" "$(cat "$SPEC/write.paths") $ERR"; fi
policy '${PROJECT_ROOT}/x' read > "$WORK/root.yaml"
run_policy --tail-flags-file "$WORK/tail.flags" --project-root "$OTHER" --config "$WORK/root.yaml"
if spec_has read.paths "$OTHER/x"; then ok '--project-root wins over the tail'"'"'s --chdir for ${PROJECT_ROOT}'; else bad '--project-root wins over the tail'"'"'s --chdir for ${PROJECT_ROOT}' "$OTHER/x" "$(cat "$SPEC/read.paths") $ERR"; fi
run_policy --tail-flags-file "$WORK/tail.flags" --project-root "$OTHER" --config "$WORK/relative.yaml"
if spec_has write.paths "$OTHER/x"; then ok "--project-root wins for a relative path too"; else bad "--project-root wins for a relative path too" "$OTHER/x" "$(cat "$SPEC/write.paths") $ERR"; fi
policy x read > "$PROJ/here.yaml"
SPEC="$(fresh_spec)"
ERR="$(cd "$PROJ" && bash "$CORE_X/phobos-policysystem.sh" --spec-dir "$SPEC" --tail-flags-file "$WORK/no-chdir.flags" --config here.yaml 2>&1 >/dev/null)"
STATUS=$?
if [[ "$STATUS" == "$PHB_EPOLICY" && "$ERR" == *"this run has no project root"* ]]; then ok "with neither, a relative path is refused, also from inside the project with the policy there"; else bad "with neither, a relative path is refused, also from inside the project with the policy there" "status ${PHB_EPOLICY}" "${STATUS}: ${ERR}"; fi
run_policy --tail-flags-file "$WORK/no-chdir.flags" --config "$WORK/root.yaml"
if [[ "$STATUS" == "$PHB_EPOLICY" && "$ERR" == *"no project root"* ]]; then ok 'with neither, ${PROJECT_ROOT} is refused'; else bad 'with neither, ${PROJECT_ROOT} is refused' "status ${PHB_EPOLICY}" "${STATUS}: ${ERR}"; fi
run_policy --tail-flags-file "$WORK/other-tail.flags" --config "$WORK/root.yaml"
if spec_has read.paths "$OTHER/x"; then ok '${PROJECT_ROOT} is the tail'"'"'s last --chdir when --project-root is not given'; else bad '${PROJECT_ROOT} is the tail'"'"'s last --chdir when --project-root is not given' "$OTHER/x" "$(cat "$SPEC/read.paths") $ERR"; fi
for root in relative/root "$WORK/does-not-exist" "" "$PROJ/../other"; do
  run_policy --project-root "$root" --config "$WORK/relative.yaml"
  if [[ "$STATUS" == "$PHB_EPOLICY" && "$ERR" == *"is not an absolute path to an existing directory"* ]]; then ok "--project-root '${root}' is refused"; else bad "--project-root '${root}' is refused" "status ${PHB_EPOLICY}" "${STATUS}: ${ERR}"; fi
done
mkdir -p "$WORK/spec-parent-empty-root"
out="$(bash "$CORE_X/phobos.sh" --tail-flags-file "$WORK/tail.flags" --spec-parent "$WORK/spec-parent-empty-root" --project-root "" \
  -nfr -nnr -ntr -nrr --config "$WORK/relative.yaml" -- /bin/true 2>&1)"
status=$?
if (( status == PHB_EPOLICY )) && [[ "$out" == *"--project-root '' is not an absolute path"* ]]; then ok "phobos.sh hands an empty --project-root on, where it is refused, rather than drop it"; else bad "phobos.sh hands an empty --project-root on, where it is refused, rather than drop it" "status ${PHB_EPOLICY}" "${status}: ${out}"; fi
DEBUG_SPEC_PARENT="$WORK/spec-parent"
mkdir -p "$DEBUG_SPEC_PARENT"
out="$(bash "$CORE_X/phobos.sh" --debug --tail-flags-file "$WORK/tail.flags" --spec-parent "$DEBUG_SPEC_PARENT" --project-root "$OTHER" \
  -nfr -nnr -ntr -nrr --config "$WORK/relative.yaml" -- /bin/true 2>&1)"
if [[ "$out" == *"project root ${OTHER}, from --project-root"* && "$out" == *"write.paths:"*"${OTHER}/x"* ]]; then ok "phobos.sh hands --project-root to the policy program"; else bad "phobos.sh hands --project-root to the policy program" "project root ${OTHER}" "$out"; fi

echo
echo "== a misnamed file is refused by both readers =="
policy allowed.txt read > "$WORK/yaml-in.cfg"
run_policy --config "$WORK/yaml-in.cfg"
if [[ "$STATUS" == "$PHB_EPOLICY" && "$ERR" == *"appears before any [section] header"* ]]; then ok "a .cfg holding YAML is refused by the .cfg reader"; else bad "a .cfg holding YAML is refused by the .cfg reader" "status ${PHB_EPOLICY}" "${STATUS}: ${ERR}"; fi
printf '[read]\n%s\n' "$OUTSIDE" > "$WORK/cfg-in.yaml"
run_policy --config "$WORK/cfg-in.yaml"
if [[ "$STATUS" == "$PHB_EPOLICY" && "$ERR" == *"is a flow collection"* ]]; then ok "a .yaml holding a cfg is refused by the YAML reader"; else bad "a .yaml holding a cfg is refused by the YAML reader" "status ${PHB_EPOLICY}" "${STATUS}: ${ERR}"; fi
cp "$WORK/outside.yaml" "$WORK/outside.yml"
run_policy --config "$WORK/outside.yml"
if [[ "$STATUS" == 0 ]] && spec_has read.paths "$OUTSIDE/data.txt"; then ok "a .yml name is read as an Ares policy too"; else bad "a .yml name is read as an Ares policy too" "status 0" "${STATUS}: ${ERR}"; fi

finish
