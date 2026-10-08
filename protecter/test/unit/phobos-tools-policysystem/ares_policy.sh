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
CORE="${HERE}/../../../src"
# shellcheck source=../../../src/phobos-tools-common/phobos-common.sh
source "${CORE}/phobos-tools-common/phobos-common.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# The scratch directory the parse helpers make their files in, which a layer sets beneath its
# specification directory; the helpers refuse to run without one.
export PHOBOS_SCRATCH="$WORK/scratch"
mkdir -p "$PHOBOS_SCRATCH"

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
for needle in "file system rows imported: 1" "network entries imported, each as a TCP and a UDP rule: 1" "a timeout of 120.000 s imported, which bounds the whole run" \
  "command entries 1, thread entries 1, package entries 1" "test classes get no exemption from Phobos"; do
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
  "::1|443|allow [::1]:443" "::1|0|allow [::1]" "::ffff:127.0.0.1|8080|allow [::ffff:127.0.0.1]:8080" "127.0.0.2|0|allow 127.0.0.2:*" "::ffff:127.0.0.1|0|allow [::ffff:127.0.0.1]" \
  "example.org|443|allow example.org:443" "*|443|allow *:443"; do
  host="${case%%|*}"
  rest="${case#*|}"
  port="${rest%%|*}"
  # ares_rule is set by ares_network_rule_line, which the library sourced above defines.
  # shellcheck disable=SC2154
  check "ares_network_rule_line ${host} ${port}" "${rest#*|}" "$( (ares_network_rule_line "$host" "$port" && printf '%s' "$ares_rule") 2>&1)"
done
for case in "example.org|0|name the port" "*|0|name the port" "10.0.0.1|0|name the port" "2001:db8::1|0|name the port" \
  "::ffff:128.0.0.1|0|name the port" "example.org.|443|drop the dot" "exa mple.org|443|neither" "-x.org|443|neither"; do
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
for flags in "true true false|openConnections sendData but not receiveData" "true false true|openConnections receiveData but not sendData" \
  "false true true|sendData receiveData but not openConnections" "true false false|openConnections but not sendData receiveData" \
  "false true false|sendData but not openConnections receiveData" "false false true|receiveData but not openConnections sendData"; do
  read -r open send receive <<< "${flags%%|*}"
  result="$(example_policy | sed "s/openConnections: true/openConnections: ${open}/; s/sendData: true/sendData: ${send}/; s/receiveData: true/receiveData: ${receive}/" | parse_result)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"grants ${flags#*|}"* && "${result#*|}" == *"policy.yaml', line 18."* ]]; then
    ok "a network entry with openConnections ${open}, sendData ${send}, receiveData ${receive} is refused at its line"
  else
    bad "a network entry with openConnections ${open}, sendData ${send}, receiveData ${receive} is refused at its line" "status ${PHB_EPOLICY}" "$result"
  fi
done
star_summary="$( (example_policy | sed 's/"www.example.com"/"*"/; s/onThePort: 80/onThePort: 443/' > "${WORK}/star.yaml"
  ares_select_language_configuration "$HOME_DIR" "${WORK}/star.yaml" && parse_ares_policy "${WORK}/star.yaml" "$PROJ" "") 2>&1 >/dev/null)"
if [[ "$star_summary" == *"permits every host on port 443, over TCP and UDP"* ]]; then ok "an entry for every host is imported with a notice naming it"; else bad "an entry for every host is imported with a notice naming it" "a notice" "$star_summary"; fi

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

for flag in overwriteAllFiles createAllFiles deleteAllFiles; do
  result="$(example_policy | sed "s/\"allowed.txt\"/\"nothere.txt\"/; s/readAllFiles: true/readAllFiles: false/; s/${flag}: false/${flag}: true/" | parse_result)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"does not exist"* && "${result#*|}" == *"policy.yaml', line 11."* ]]; then
    ok "a missing path granted only ${flag} is refused, never created"
  else
    bad "a missing path granted only ${flag} is refused, never created" "status ${PHB_EPOLICY}" "$result"
  fi
done

echo "== the shapes of the Ares 2 repository's example policies =="
# The example policies of the Ares 2 repository (examples/ares-exercise-gradle and -maven, at the commit named above),
# rewritten here: the path key after the five flags, "[ ]" for an empty list, comments between keys.
ares_example_shape() {
  cat <<POLICY
thisPolicyFileCompliesToThePolicyVersion: 1
regardingTheSupervisedCode:
  theFollowingProgrammingLanguageConfigurationIsUsed: $1
  theSupervisedCodeUsesTheFollowingPackage: "org.example"
  theMainClassInsideThisPackageIs: "Penguin"
  theFollowingClassesAreTestClasses:
    - "org.example.PenguinTest"
  theFollowingResourceAccessesArePermitted:
    # one permitted file, on purpose
    regardingFileSystemInteractions:
      - readAllFiles: true
        overwriteAllFiles: false
        createAllFiles: false
        executeAllFiles: false
        deleteAllFiles: false
        onThisPathAndAllPathsBelow: "allowed.txt"
    regardingNetworkConnections: [ ]
    regardingCommandExecutions: [ ]
    regardingThreadCreations: [ ]
    regardingPackageImports: [ ]
    regardingTimeouts:
      - timeout: 3000
POLICY
}
result="$(ares_example_shape TEST_CONFIGURATION | parse_result)"
check "the Gradle example's shape reads its one file" "${PROJ}/allowed.txt " "$(field read "$result")"
check "and imports its 3000 ms as 3.000 s, which bounds the whole run" "3.000" "$(field timeout "$result")"
result="$(ares_example_shape JAVA_USING_MAVEN_ARCHUNIT_AND_ASPECTJ | parse_result)"
if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"has no file 'language-configurations/JAVA_USING_MAVEN_ARCHUNIT_AND_ASPECTJ.cfg'"* ]]; then
  ok "the Maven example is refused for want of its programming language configuration"
else
  bad "the Maven example is refused for want of its programming language configuration" "status ${PHB_EPOLICY}" "$result"
fi
result="$(example_policy | sed '/^    regardingFileSystemInteractions:$/,/^    regardingNetworkConnections:$/{/^    regardingNetworkConnections:$/!d}' \
  | sed 's/^    regardingNetworkConnections:$/    regardingFileSystemInteractions: []\n    regardingNetworkConnections: []/' \
  | sed '/^      - onTheHost/,/^        receiveData/d; /^    regardingTimeouts:$/,$d' | { cat; printf '    regardingTimeouts: []\n'; } | parse_result)"
check "a policy that maps to nothing but notices still parses, and grants nothing" "TEST_CONFIGURATION|||" "$(field configuration "$result")|$(field read "$result")|$(field net "$result")|$(field timeout "$result")"

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

echo "== a symbolic link inside the project root =="
# The project root usually holds the submission's checkout, so a link there would redirect a grant. A link outside it,
# the way /bin is a link to /usr/bin, is not the submission's to place.
ln -s "$OUTSIDE" "${WORK}/link-to-outside"
: > "${PROJ}/dir/inside.txt"
for value in "link/data.txt" "link" "${PROJ}/link/data.txt"; do
  result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' "      - onThisPathAndAllPathsBelow: \"${value}\"" | parse_result)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"reaches the project root"* && "${result#*|}" == *"resolves to '${OUTSIDE}"* && "${result#*|}" == *"policy.yaml', line 11."* ]]; then
    ok "refused at its line: ${value}"
  else
    bad "refused at its line: ${value}" "status ${PHB_EPOLICY}, a link inside the project root" "$result"
  fi
done
ln -s "$OUTSIDE" "${PROJ}/dir/deeper-link"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' '      - onThisPathAndAllPathsBelow: "dir/deeper-link/data.txt"' | parse_result)"
if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"reaches the project root"* && "${result#*|}" == *"resolves to '${OUTSIDE}"* && "${result#*|}" == *"policy.yaml', line 11."* ]]; then ok "a link several components down is refused too"; else bad "a link several components down is refused too" "status ${PHB_EPOLICY}" "$result"; fi
# A link inside the project root that points to somewhere else inside it still lands the grant where the submission chose.
ln -s "${PROJ}/dir" "${PROJ}/alias"
refused_path() {
  local title="$1"
  local value="$2"
  local root="$3"
  local result
  result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' "      - onThisPathAndAllPathsBelow: \"${value}\"" | parse_result "$root")"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"reaches the project root"* && "${result#*|}" == *"policy.yaml', line 11."* ]]; then
    ok "refused at its line: ${title}"
  else
    bad "refused at its line: ${title}" "status ${PHB_EPOLICY}, reaches the project root" "$result"
  fi
}
refused_path "a link inside the root to another place inside it" "alias/inside.txt" "$PROJ"
refused_path "the same, written with a trailing slash on the root and a dot in the path" "./alias/inside.txt" "${PROJ}/"
ln -s "$PROJ" "${WORK}/root-link"
root_refused() {
  local title="$1"
  local value="$2"
  local root="$3"
  local needle="$4"
  local result
  result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' "      - onThisPathAndAllPathsBelow: \"${value}\"" | parse_result "$root")"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"must be the real path of a project directory"* && "${result#*|}" == *"${needle}"* && "${result#*|}" == *"policy.yaml', line 11."* ]]; then
    ok "refused at its line: ${title}"
  else
    bad "refused at its line: ${title}" "status ${PHB_EPOLICY}, must be the real path of a project directory, ${needle}" "$result"
  fi
}
root_refused "a project root that is itself a link" "dir/inside.txt" "${WORK}/root-link" "resolves to '${PROJ}'"
root_refused "the same for an absolute path written with the root's real name" "${PROJ}/dir/inside.txt" "${WORK}/root-link" "resolves to '${PROJ}'"
root_refused "a project root that is the root of the file system" "/usr/bin/env" "/" "the root of the file system"
mkdir -p "${WORK}/real-parent"
ln -s "${PROJ}" "${WORK}/real-parent/hop"
root_refused "a project root with a link in the middle of its path" "dir/inside.txt" "${WORK}/real-parent/hop" "resolves to '${PROJ}'"
ln -s "$PROJ" "${WORK}/alias-of-root"
refused_path "a path written through a name of the root that is not the operator's, with a link below it" "${WORK}/alias-of-root/dir/deeper-link/data.txt" "$PROJ"
ln -s "${PROJ}/dir" "${WORK}/outside-link-into-root"
refused_path "a link outside the root that points into it" "${WORK}/outside-link-into-root/inside.txt" "$PROJ"
mkdir -p "${PROJ}2/dir"
: > "${PROJ}2/dir/sibling.txt"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' "      - onThisPathAndAllPathsBelow: \"${PROJ}2/dir/sibling.txt\"" | parse_result)"
check "a sibling whose name starts with the root's is not inside it" "${PROJ}2/dir/sibling.txt " "$(field read "$result")"
ln -s "$OUTSIDE" "${PROJ}2/dir/link-to-outside"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' "      - onThisPathAndAllPathsBelow: \"${PROJ}2/dir/link-to-outside/data.txt\"" | parse_result)"
check "and a link inside that sibling is not a link inside the root" "${PROJ}2/dir/link-to-outside/data.txt " "$(field read "$result")"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' "      - onThisPathAndAllPathsBelow: \"${WORK}/alias-of-root/dir/inside.txt\"" | parse_result)"
check "a name for the root that resolves exactly to it, with real components below, lands where the path says and is allowed" "${WORK}/alias-of-root/dir/inside.txt " "$(field read "$result")"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' '      - onThisPathAndAllPathsBelow: "dir/inside.txt"' | parse_result "${PROJ}/")"
check "a project root with a trailing slash does not change what is allowed" "${PROJ}/dir/inside.txt " "$(field read "$result")"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' '      - onThisPathAndAllPathsBelow: "dir/inside.txt"' | parse_result "${PROJ}/../proj")"
if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"holds a '..' segment"* ]]; then ok "a project root with a '..' segment is refused"; else bad "a project root with a '..' segment is refused" "status ${PHB_EPOLICY}" "$result"; fi
if [[ -L /bin ]]; then
  result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' '      - onThisPathAndAllPathsBelow: "/bin/true"' | parse_result "")"
  check "with no project root nothing lies inside it, and /bin/true, through the /bin link of the image, is written" "/bin/true " "$(field read "$result")"
  result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' '      - onThisPathAndAllPathsBelow: "/bin/true"' | parse_result)"
  check "and with a project root elsewhere /bin/true is written too: the link is not the submission's" "/bin/true " "$(field read "$result")"
else
  skip "paths through the /bin link of the image" "/bin is not a symbolic link in this image"
fi
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' "      - onThisPathAndAllPathsBelow: \"${WORK}/link-to-outside/data.txt\"" | parse_result)"
check "a link outside the project root is allowed, and written as written" "${WORK}/link-to-outside/data.txt " "$(field read "$result")"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' '      - onThisPathAndAllPathsBelow: "dir"' | parse_result)"
check "a real path inside the project root is written as it was" "${PROJ}/dir " "$(field read "$result")"

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
# A link outside the project root to a directory beneath a base row: lexically the imported path is under no base row,
# but resolved it is under one, so a skip by resolved comparison leaves it out and a lexical one would write it.
mkdir -p "${WORK}/covered-target"
: > "${WORK}/covered-target/inside.txt"
ln -s "${WORK}/covered-target" "${WORK}/link-to-covered"
printf '%s\n' "${WORK}/covered-target" > "${BASE}/read.paths"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' "      - onThisPathAndAllPathsBelow: \"${WORK}/link-to-covered/inside.txt\"" | parse_result "$PROJ" "$BASE")"
check "a row reached through a link outside the project root is judged by where it resolves, and left out as covered there" "|1" "$(field read "$result")|$(field skipped "$result")"
# The other direction: lexically under a base row, resolved elsewhere, so a skip by the lexical comparison would drop a grant.
mkdir -p "${WORK}/baseA" "${WORK}/escaped"
: > "${WORK}/escaped/f"
ln -s "${WORK}/escaped" "${WORK}/baseA/escape"
printf '%s\n' "${WORK}/baseA" > "${BASE}/read.paths"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' "      - onThisPathAndAllPathsBelow: \"${WORK}/baseA/escape/f\"" | parse_result "$PROJ" "$BASE")"
check "a row lexically under a base row that resolves elsewhere is written, not skipped" "${WORK}/baseA/escape/f |0" "$(field read "$result")|$(field skipped "$result")"
printf '%s\n' "${WORK}/not-covering" > "${BASE}/read.paths"
result="$(policy_with '      - onThisPathAndAllPathsBelow: "allowed.txt"' "      - onThisPathAndAllPathsBelow: \"${WORK}/link-to-outside/data.txt\"" | parse_result "$PROJ" "$BASE")"
check "and one that resolves outside every base row is written as written" "${WORK}/link-to-outside/data.txt |0" "$(field read "$result")|$(field skipped "$result")"
printf '%s\n%s\n' "$PROJ" "${WORK}/missing" > "${BASE}/read.paths"
mkdir -p "${WORK}/missing-parent-test"
: > "${WORK}/missing-parent-test/f"
# Resolved without asking that it exists, this base row would name the directory that holds the imported file.
printf '%s\n' "${WORK}/missing-parent-test/gone/.." > "${BASE}/read.paths"
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
