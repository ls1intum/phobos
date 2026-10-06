#!/usr/bin/env bash
# How an Ares 2 security policy becomes the parsed state a policy cfg gives. Every field the import
# maps is mapped as the table of the plan says, every field it does not map is checked for its
# structure, and every element whose translation would widen or narrow the sandbox without saying
# so is refused with its line. The schema is Ares 2 at commit 18062fca42a5e337ec63b30655497c4071f765f8
# (ls1intum/Ares2, 2026-10-05), version 1. This suite pins both directions.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../../core"
# shellcheck source=../../../core/phobos-tools-common/phobos-common.sh
source "${CORE}/phobos-tools-common/phobos-common.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

HOME_DIR="${WORK}/home"
PROJ="${WORK}/proj"
OUTSIDE="${WORK}/outside"
mkdir -p "${HOME_DIR}/language-configurations" "${PROJ}/dir" "$OUTSIDE"
: > "${HOME_DIR}/BaseLanguage-x.cfg"
: > "${PROJ}/allowed.txt"
: > "${PROJ}/x"
: > "${OUTSIDE}/data.txt"
ln -s "$OUTSIDE" "${PROJ}/link"
cat > "${HOME_DIR}/language-configurations/TEST_CONFIGURATION.cfg" <<EOF
[base]
BaseLanguage-x.cfg
[placeholders]
work.dir = fixed ${PROJ}
[connect]
allow localhost udp
EOF

# The example policy of the plan's A.1, with the configuration this suite ships.
example_policy() {
  cat <<'POLICY'
thisPolicyFileCompliesToThePolicyVersion: 1
regardingTheSupervisedCode:
  theFollowingProgrammingLanguageConfigurationIsUsed: TEST_CONFIGURATION
  theSupervisedCodeUsesTheFollowingPackage: "org.example"
  theMainClassInsideThisPackageIs: "Main"
  theFollowingClassesAreTestClasses:
    - "org.example.PenguinTest"
  theFollowingTestBehaviorIsConfigured: {}
  theFollowingResourceAccessesArePermitted:
    regardingFileSystemInteractions:
      - onThisPathAndAllPathsBelow: "allowed.txt"
        readAllFiles: true
        overwriteAllFiles: false
        createAllFiles: false
        executeAllFiles: false
        deleteAllFiles: false
    regardingNetworkConnections:
      - onTheHost: "www.example.com"
        onThePort: 80
        openConnections: true
        sendData: true
        receiveData: true
    regardingCommandExecutions:
      - executeTheCommand: "ls"
        withTheseArguments:
          - "-l"
    regardingThreadCreations:
      - createTheFollowingNumberOfThreads: 10
        ofThisClass: "org.example.Worker"
    regardingPackageImports:
      - importTheFollowingPackage: "org.example.util"
    regardingTimeouts:
      - timeout: 120000
POLICY
}

# Prints the example policy with every line equal to the first argument replaced by the second,
# whose \n become line breaks; an empty second argument removes the line.
policy_with() {
  local from="$1"
  local to="$2"
  local line
  while IFS= read -r line; do
    if [[ "$line" == "$from" ]]; then
      [[ -z "$to" ]] || printf '%b\n' "$to"
    else
      printf '%s\n' "$line"
    fi
  done < <(example_policy)
}

# Writes standard input as a policy, selects and loads its configuration, imports it with the
# project root and the base directory given, and prints what it wrote, one line per file, or
# "<status>|<message>" when it is refused.
parse_result() {
  local root="${1-$PROJ}"
  local base="${2:-}"
  local file="${WORK}/policy.yaml"
  local message
  local right
  cat > "$file"
  message="$( (ares_select_language_configuration "$HOME_DIR" "$file" && parse_ares_policy "$file" "$root" "$base" \
    && for right in read write create symlink execute delete refer; do printf '%s: %s\n' "$right" "$(tr '\n' ' ' < "${PARSED_FS_DIR}/${right}.paths")"; done \
    && printf 'net: %s\n' "$(tr '\n' ',' < "$PARSED_NET_FILE")" \
    && printf 'timeout: %s\nskipped: %s\nconfiguration: %s\n' "$PARSED_TIMEOUT" "$PARSED_ARES_SKIPPED" "$PARSED_ARES_CONFIGURATION") 2>&1)"
  local status=$?
  if (( status == 0 )); then printf '%s' "$message"; else printf '%s|%s' "$status" "$message"; fi
}

# Prints one line of a parse_result output: the one starting with the label given.
field() {
  sed -n "s/^$1: //p" <<< "$2"
}

echo "== the example policy =="
result="$(example_policy | parse_result)"
check "readAllFiles on a relative path reads it below the project root" "${PROJ}/allowed.txt " "$(field read "$result")"
check "nothing else is written for it" "" "$(field write "$result")$(field create "$result")$(field symlink "$result")$(field execute "$result")$(field delete "$result")$(field refer "$result")"
check "a granted network entry becomes a TCP and a UDP rule" "www.example.com 80,www.example.com 80 udp," "$(field net "$result")"
check "120000 ms becomes 120.000 s" "120.000" "$(field timeout "$result")"
check "the configuration it names is recorded" "TEST_CONFIGURATION" "$(field configuration "$result")"
summary="$( (ares_select_language_configuration "$HOME_DIR" "${WORK}/policy.yaml" && parse_ares_policy "${WORK}/policy.yaml" "$PROJ" "") 2>&1 >/dev/null)"
for needle in "1 file system rows imported" "1 network entries imported" "a timeout of 120.000 s imported, which bounds the whole run" \
  "1 command, 1 thread and 1 package entries" "test classes get no exemption from Phobos"; do
  if [[ "$summary" == *"$needle"* ]]; then ok "the summary line says: ${needle}"; else bad "the summary line says: ${needle}" "$needle" "$summary"; fi
done

echo "== the file system mapping =="
for case in "true true true true true|read write create symlink execute delete refer" "false false true false false|create symlink" \
  "false false true false true|create symlink delete refer" "false true false false false|write" "false false false true false|execute" \
  "false false false false true|delete" "false false false false false|"; do
  read -r r w c x d <<< "${case%%|*}"
  want="${case#*|}"
  result="$(example_policy | sed "s/readAllFiles: true/readAllFiles: ${r}/; s/overwriteAllFiles: false/overwriteAllFiles: ${w}/; s/createAllFiles: false/createAllFiles: ${c}/; s/executeAllFiles: false/executeAllFiles: ${x}/; s/deleteAllFiles: false/deleteAllFiles: ${d}/; s|\"allowed.txt\"|\"dir\"|" | parse_result)"
  got=""
  for right in read write create symlink execute delete refer; do
    [[ -n "$(field "$right" "$result")" ]] && got+=" ${right}"
  done
  check "readAllFiles ${r}, overwriteAllFiles ${w}, createAllFiles ${c}, executeAllFiles ${x}, deleteAllFiles ${d} write ${want:-nothing}" "$want" "${got# }"
done

result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' '      - onThisPathAndAllPathsBelow: "${PROJECT_ROOT}/x"' | parse_result)"
check '${PROJECT_ROOT} is the project root' "${PROJ}/x " "$(field read "$result")"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' '      - onThisPathAndAllPathsBelow: "${work.dir}/dir"' | parse_result)"
check 'a placeholder the configuration names is the value it determines' "${PROJ}/dir " "$(field read "$result")"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' "      - onThisPathAndAllPathsBelow: \"${OUTSIDE}/data.txt\"" | parse_result "")"
check "an absolute path needs no project root" "${OUTSIDE}/data.txt " "$(field read "$result")"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' '      - onThisPathAndAllPathsBelow: "./dir/"' | parse_result)"
check "a path is made absolute and canonical later, by the merge, as a cfg path is" "${PROJ}/./dir/ " "$(field read "$result")"

echo "== the timeout =="
for case in "1|0.001" "999|0.999" "1000|1.000" "1500|1.500" "120000|120.000" "000120000|120.000" "999999999999999999|999999999999999.999"; do
  check "ares_millis_to_timeout ${case%%|*}" "${case##*|}" "$(ares_millis_to_timeout "${case%%|*}")"
done
result="$(policy_with '      - timeout: 120000' '      - timeout: 3000\n      - timeout: 1000\n      - timeout: 2000' | parse_result)"
check "the tightest of a policy's timeouts wins, as in Ares" "1.000" "$(field timeout "$result")"
{ example_policy | sed '/^    regardingTimeouts:$/,$d'; printf '    regardingTimeouts: []\n'; } > "${WORK}/empty.yaml"
result="$(parse_result < "${WORK}/empty.yaml")"
check "an empty timeout list imports no timeout" "" "$(field timeout "$result")"
summary="$( (ares_select_language_configuration "$HOME_DIR" "${WORK}/empty.yaml" && parse_ares_policy "${WORK}/empty.yaml" "$PROJ" "") 2>&1 >/dev/null)"
if [[ "$summary" == *"no timeout imported"* ]]; then ok "and says so"; else bad "and says so" "no timeout imported" "$summary"; fi

echo "== the network mapping =="
for case in "localhost|80|allow localhost:80" "localhost|0|allow localhost" "127.0.0.1|0|allow 127.0.0.1:*" "10.0.0.1|53|allow 10.0.0.1:53" \
  "::1|443|allow [::1]:443" "::1|0|allow [::1]" "::ffff:127.0.0.1|8080|allow [::ffff:127.0.0.1]:8080" \
  "example.org|443|allow example.org:443" "*|443|allow *:443"; do
  host="${case%%|*}"
  rest="${case#*|}"
  port="${rest%%|*}"
  # ares_rule is set by ares_network_rule_line, which the library sourced above defines.
  # shellcheck disable=SC2154
  check "ares_network_rule_line ${host} ${port}" "${rest#*|}" "$( (ares_network_rule_line "$host" "$port" && printf '%s' "$ares_rule") 2>&1)"
done
for case in "example.org|0|name the port" "*|0|name the port" "example.org.|443|drop the dot" "exa mple.org|443|neither" "-x.org|443|neither"; do
  host="${case%%|*}"
  rest="${case#*|}"
  port="${rest%%|*}"
  if result="$( (ares_network_rule_line "$host" "$port") 2>&1)"; then status=0; else status=$?; fi
  if (( status == PHB_EPOLICY )) && [[ "$result" == *"${rest#*|}"* ]]; then ok "refused: ${host} ${port}"; else bad "refused: ${host} ${port}" "status ${PHB_EPOLICY}" "${status}|${result}"; fi
done
result="$(example_policy | sed 's/"www.example.com"/"localhost"/; s/onThePort: 80/onThePort: 0/' | parse_result)"
check "localhost with port 0 becomes a TCP and a UDP rule for every port" "localhost *,localhost * udp," "$(field net "$result")"
result="$(example_policy | sed 's/openConnections: true/openConnections: false/; s/sendData: true/sendData: false/; s/receiveData: true/receiveData: false/' | parse_result)"
check "an entry with all three flags false grants nothing" "" "$(field net "$result")"

echo "== refused =="
for case in \
  'thisPolicyFileCompliesToThePolicyVersion: 1|thisPolicyFileCompliesToThePolicyVersion: 2|exactly 1' \
  'thisPolicyFileCompliesToThePolicyVersion: 1|thisPolicyFileCompliesToThePolicyVersion: "1"|exactly 1' \
  'thisPolicyFileCompliesToThePolicyVersion: 1|thisPolicyFileCompliesToThePolicyVersion: 1\nextra: 1|unknown key' \
  '    regardingTimeouts:|    regardingTimeoutz:|unknown key' \
  '        readAllFiles: true|        readAllFiles: "true"|must be true or false' \
  '        readAllFiles: true||has no key '"'"'readAllFiles'"'" \
  '        onThePort: 80|        onThePort: "80"|whole number' \
  '        onThePort: 80|        onThePort: 70000|from 0 to 65535' \
  '        onThePort: 80|        onThePort: 0|name the port' \
  '  theFollowingTestBehaviorIsConfigured: {}|  theFollowingTestBehaviorIsConfigured:|must be a mapping' \
  '  theFollowingTestBehaviorIsConfigured: {}|  theFollowingTestBehaviorIsConfigured:\n    x: 1|unknown key' \
  '  theFollowingProgrammingLanguageConfigurationIsUsed: TEST_CONFIGURATION|  theFollowingProgrammingLanguageConfigurationIsUsed: PYTHON_USING_PIP|has no file' \
  '  theFollowingProgrammingLanguageConfigurationIsUsed: TEST_CONFIGURATION|  theFollowingProgrammingLanguageConfigurationIsUsed: test_configuration|is not the name of a programming language configuration' \
  '    - "org.example.PenguinTest"|    - ""|must not be empty' \
  '    - "org.example.PenguinTest"|    - "${work.dir}"|holds a placeholder' \
  '  theSupervisedCodeUsesTheFollowingPackage: "org.example"|  theSupervisedCodeUsesTheFollowingPackage: "${work.dir}"|holds a placeholder' \
  '  theSupervisedCodeUsesTheFollowingPackage: "org.example"|  theSupervisedCodeUsesTheFollowingPackage: 7|must be text' \
  '      - onTheHost: "www.example.com"|      - onTheHost: "${work.dir}"|holds a placeholder' \
  '      - onTheHost: "www.example.com"|      - onTheHost: "example.org."|drop the dot' \
  '      - executeTheCommand: "ls"|      - executeTheCommand: "ls"\n        extra: 1|unknown key' \
  '      - createTheFollowingNumberOfThreads: 10|      - createTheFollowingNumberOfThreads: "10"|whole number' \
  '      - importTheFollowingPackage: "org.example.util"|      - importTheFollowingPackage: "${work.dir}"|holds a placeholder' \
  '      - onThisPathAndAllPathsBelow: "allowed.txt"|      - onThisPathAndAllPathsBelow: "*"|whole file system' \
  '      - onThisPathAndAllPathsBelow: "allowed.txt"|      - onThisPathAndAllPathsBelow: "a\\\\b"|backslash' \
  '      - onThisPathAndAllPathsBelow: "allowed.txt"|      - onThisPathAndAllPathsBelow: "${HOME}/x"|is not a placeholder the programming language configuration' \
  '      - onThisPathAndAllPathsBelow: "allowed.txt"|      - onThisPathAndAllPathsBelow: "${work.dir/x"|does not close' \
  '      - onThisPathAndAllPathsBelow: "allowed.txt"|      - onThisPathAndAllPathsBelow: "../x"|segment' \
  '      - onThisPathAndAllPathsBelow: "allowed.txt"|      - onThisPathAndAllPathsBelow: "x/../y"|segment' \
  '      - onThisPathAndAllPathsBelow: "allowed.txt"|      - onThisPathAndAllPathsBelow: "nothere.txt"|does not exist' \
  '      - onThisPathAndAllPathsBelow: "allowed.txt"|      - onThisPathAndAllPathsBelow: "dir/*"|wildcard' \
  '      - onThisPathAndAllPathsBelow: "allowed.txt"|      - onThisPathAndAllPathsBelow: ""|must not be empty' \
  '        sendData: true|        sendData: false|grants openConnections receiveData but not sendData' \
  '        openConnections: true|        openConnections: false|grants sendData receiveData but not openConnections' \
  '      - timeout: 120000|      - timeout: 0|at least 1' \
  '      - timeout: 120000|      - timeout: 9223372036854775807|digits of seconds' \
  '      - timeout: 120000|      - timeout: "120000"|whole number' \
  '    - "org.example.PenguinTest"|    - 7|must be text' \
  '          - "-l"|          - ""|must not be empty'; do
  from="${case%%|*}"
  rest="${case#*|}"
  to="${rest%|*}"
  needle="${rest##*|}"
  result="$(policy_with "$from" "$to" | parse_result)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"${needle}"* && "${result#*|}" == *"policy.yaml', line "* ]]; then
    ok "refused, saying '${needle}', with file and line: ${to:-without ${from# *}}"
  else
    bad "refused, saying '${needle}', with file and line: ${to:-without ${from# *}}" "status ${PHB_EPOLICY}" "${result}"
  fi
done

echo "== accepted, though Phobos grants nothing for it =="
result="$(policy_with '      - executeTheCommand: "ls"' '      - "${work.dir}/run"\n      - executeTheCommand: "ls"' | parse_result)"
check 'a bare command, with a placeholder Phobos does not expand, is accepted' "120.000" "$(field timeout "$result")"
result="$(policy_with '  theSupervisedCodeUsesTheFollowingPackage: "org.example"' '  theSupervisedCodeUsesTheFollowingPackage: null' | parse_result)"
check 'a null package is accepted' "120.000" "$(field timeout "$result")"
result="$(policy_with '  theFollowingTestBehaviorIsConfigured: {}' '' | parse_result)"
check 'an absent test behaviour is accepted' "120.000" "$(field timeout "$result")"

echo "== the project root =="
result="$(example_policy | parse_result "")"
if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "$result" == *"this run has no project root to resolve 'allowed.txt' against"* ]]; then ok "a relative path with no project root is refused"; else bad "a relative path with no project root is refused" "status ${PHB_EPOLICY}" "$result"; fi
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' '      - onThisPathAndAllPathsBelow: "${PROJECT_ROOT}/x"' | parse_result "")"
if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "$result" == *"no project root"* ]]; then ok '${PROJECT_ROOT} with no project root is refused'; else bad '${PROJECT_ROOT} with no project root is refused' "status ${PHB_EPOLICY}" "$result"; fi
result="$(example_policy | parse_result "relative/root")"
if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "$result" == *"is relative"* ]]; then ok "a relative project root is refused where a path needs it"; else bad "a relative project root is refused where a path needs it" "status ${PHB_EPOLICY}" "$result"; fi
printf -- '--foo\n--chdir /first # --chdir /comment\n--chdir /second\n' > "${WORK}/tail.flags"
check "the tail flags give their last --chdir, not one in a comment" "/second" "$(tail_flags_working_directory "${WORK}/tail.flags")"
printf -- '--foo\n' > "${WORK}/none.flags"
check "tail flags with no --chdir give nothing" "" "$(tail_flags_working_directory "${WORK}/none.flags")"
check "absent tail flags give nothing" "" "$(tail_flags_working_directory "${WORK}/absent.flags")"

echo "== the covered-entry skip =="
BASE="${WORK}/base"
mkdir -p "$BASE"
for right in ${PHB_FS_RIGHTS}; do : > "${BASE}/${right}.paths"; done
printf '%s\n%s\n' "$PROJ" "${WORK}/missing" > "${BASE}/read.paths"
result="$(example_policy | parse_result "$PROJ" "$BASE")"
check "a row the base covers through an ancestor is not written" "" "$(field read "$result")"
check "and is counted" "1" "$(field skipped "$result")"
result="$(policy_with '        overwriteAllFiles: false' '        overwriteAllFiles: true' | parse_result "$PROJ" "$BASE")"
check "a right the base does not grant there is written" "${PROJ}/allowed.txt " "$(field write "$result")"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' '      - onThisPathAndAllPathsBelow: "link/data.txt"' | parse_result "$PROJ" "$BASE")"
check "a row whose ancestor is only lexical, through a symbolic link, is written" "${PROJ}/link/data.txt " "$(field read "$result")"
mkdir -p "${WORK}/missing-parent-test"
: > "${WORK}/missing-parent-test/f"
printf '%s\n' "${WORK}/missing-parent-test/gone" > "${BASE}/read.paths"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' "      - onThisPathAndAllPathsBelow: \"${WORK}/missing-parent-test/f\"" | parse_result "$PROJ" "$BASE")"
check "a base path that does not exist covers nothing" "${WORK}/missing-parent-test/f " "$(field read "$result")"

echo "== the programming language configuration =="
cp "${HOME_DIR}/language-configurations/TEST_CONFIGURATION.cfg" "${HOME_DIR}/language-configurations/OTHER_CONFIGURATION.cfg"
example_policy > "${WORK}/first.yaml"
example_policy | sed 's/TEST_CONFIGURATION/OTHER_CONFIGURATION/' > "${WORK}/second.yaml"
if result="$( (ares_select_language_configuration "$HOME_DIR" "${WORK}/first.yaml" "${WORK}/second.yaml") 2>&1)"; then status=0; else status=$?; fi
if (( status == PHB_EPOLICY )) && [[ "$result" == *"one run has one base and one set of placeholder values"* && "$result" == *"second.yaml', line 3."* ]]; then
  ok "two policies naming different configurations are refused, also when their bases agree"
else
  bad "two policies naming different configurations are refused, also when their bases agree" "status ${PHB_EPOLICY}" "${status}|${result}"
fi
result="$( (ares_select_language_configuration "$HOME_DIR" "${WORK}/first.yaml" "${WORK}/first.yaml" && printf '%s %s' "$ARES_SELECTED_CONFIGURATION" "${LANGUAGE_CONFIGURATION_BASES[*]##*/}" && cat "$LANGUAGE_CONFIGURATION_CONNECT_FILE") 2>&1)"
check "two policies naming the same configuration select it, its base and its [connect] rows" "TEST_CONFIGURATION BaseLanguage-x.cfglocalhost * udp" "$result"
result="$( (ares_select_language_configuration "$HOME_DIR" "${WORK}/some.cfg" && printf '[%s]' "$ARES_SELECTED_CONFIGURATION") 2>&1)"
check "a run with no Ares policy selects no configuration" "[]" "$result"

finish
