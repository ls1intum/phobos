#!/usr/bin/env bash
# What phobos-policysystem.sh says to a configuration file that is wrong. Every malformed input has to
# end the run with PHB-EPOLICY before anything is written, say what is wrong in words, say where, and
# never let a bash error or a raw byte of the file reach the terminal. The controls beside the refusals
# are well-formed inputs of the same shapes, so a parser that refuses everything cannot pass.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../core"
# shellcheck source=../../core/phobos-tools-common/phobos-constants.sh
source "${CORE}/phobos-tools-common/phobos-constants.sh"
WORK="$(mktemp -d)"
export TMPDIR="$WORK"
trap 'rm -rf "$WORK"' EXIT

CORE_X="${WORK}/core-x"
cp -R "$CORE" "$CORE_X"
CORE_B="${WORK}/core-b"
cp -R "$CORE" "$CORE_B"
chmod +x "$CORE_X"/*.sh
printf '[read]\n/usr\n[execute]\n/usr\n' > "${CORE_X}/BaseTest.cfg"
chmod +x "$CORE_B"/*.sh
printf '[read]\n/usr\n/nonexistent/in-the-base\n[execute]\n/usr\n[connect]\nallow 127.0.0.1:*\n' > "${CORE_B}/BaseTest.cfg"

# A UTF-8 locale where there is one, because the digit classes only matter there: in en_US.UTF-8 a
# range such as [0-9] matched Arabic-Indic digits, which the arithmetic after it then could not read.
UTF8_LOCALE="C.UTF-8"
if locale -a 2> /dev/null | grep -qix 'en_US.utf-\?8'; then UTF8_LOCALE="en_US.UTF-8"; fi

# The core directory run_cfg uses and a directory put in front of PATH while it runs, empty for none.
RUN_CORE="$CORE_X"
RUN_PATH_PREFIX=""
RUN_STATUS=0
RUN_ERR=""
RUN_WRITTEN=0
# run_cfg FILE: builds a specification from the file and keeps the status and what was said on standard error.
run_cfg() {
  local spec
  spec="$(mktemp -d "${WORK}/spec.XXXXXX")"
  RUN_ERR="$(PATH="${RUN_PATH_PREFIX:+${RUN_PATH_PREFIX}:}${PATH}" LC_ALL="$UTF8_LOCALE" bash "${RUN_CORE}/phobos-policysystem.sh" --spec-dir "$spec" --config "$1" 2>&1 > /dev/null)"
  RUN_STATUS=$?
  RUN_WRITTEN="$(find "$spec" -maxdepth 1 -name '*.paths' | wc -l)"
  rm -rf "$spec"
}
# cfg_text FORMAT [ARGUMENT...]: writes what printf makes of them to a file, and prints the path. The format is the
# caller's on purpose: the cases write escapes such as \xef and \0 that only printf makes into bytes.
# shellcheck disable=SC2059
cfg_text() {
  local file
  file="$(mktemp "${WORK}/cfg.XXXXXX")"
  printf -- "$@" > "$file"
  printf '%s' "$file"
}
# noise_free: whether the last message is free of what a bash error looks like: an arithmetic complaint, a line
# of a script, an error of another program, a control character, or bytes that are not valid UTF-8. A value written
# in valid UTF-8 may be quoted as it is, since it is text a terminal shows properly.
noise_free() {
  [[ "$RUN_ERR" != *"syntax error"* && "$RUN_ERR" != *"invalid integer"* && "$RUN_ERR" != *"operand expected"* \
    && "$RUN_ERR" != *"realpath:"* && ! "$RUN_ERR" =~ \.sh:\ line\ [0-9]+: ]] && ! printf '%s' "$RUN_ERR" | LC_ALL=C grep -q -P '[\x00-\x08\x0b-\x1f]' \
    && printf '%s' "$RUN_ERR" | iconv -f UTF-8 -t UTF-8 > /dev/null 2>&1
}
# refused TITLE FILE FRAGMENT...: the file ends the run with PHB-EPOLICY before a specification is written, the message
# holds every fragment, a fragment that names a line comes with the name of the file, and the message is clean.
refused() {
  local title="$1"
  local file="$2"
  shift 2
  local fragment
  local missing=""
  run_cfg "$file"
  for fragment in "$@"; do
    [[ "$RUN_ERR" == *"$fragment"* ]] || missing="${missing} [${fragment}]"
    [[ "$fragment" != "line "* || "$RUN_ERR" == *"$file"* ]] || missing="${missing} [the name of the file ${file}]"
  done
  (( RUN_WRITTEN == 0 )) || missing="${missing} [nothing written, but ${RUN_WRITTEN} specification files were]"
  if (( RUN_STATUS == PHB_EPOLICY )) && [[ -z "$missing" ]] && noise_free; then
    ok "refused: ${title}"
  else
    bad "refused: ${title}" "status ${PHB_EPOLICY} and the fragments${*:+ $*}, no bash noise" "status ${RUN_STATUS}, missing${missing:- nothing}: ${RUN_ERR}"
  fi
}
# accepted TITLE FILE: the file builds a specification.
accepted() {
  run_cfg "$2"
  if (( RUN_STATUS == 0 )); then ok "accepted: ${1}"; else bad "accepted: ${1}" "status 0" "status ${RUN_STATUS}: ${RUN_ERR}"; fi
}

echo "== a configuration that is not a readable file =="
refused "a path that names nothing" "${WORK}/missing.cfg" "does not exist" "missing.cfg"
refused "an empty path" "" "empty path"
mkdir "${WORK}/dir.cfg"
refused "a directory" "${WORK}/dir.cfg" "is a directory"
ln -s "${WORK}/nowhere" "${WORK}/dangling.cfg"
refused "a symbolic link to nothing" "${WORK}/dangling.cfg" "symbolic link to nothing"
refused "a device" /dev/null "not a regular file"
printf '[read]\n/usr\n' > "${WORK}/ok.cfg"
ln -s "${WORK}/ok.cfg" "${WORK}/link.cfg"
accepted "a symbolic link to a file" "${WORK}/link.cfg"
if (( $(id -u) == 0 )); then
  skip "a file this user may not read" "running as root, which reads every file"
else
  printf '[read]\n/usr\n' > "${WORK}/secret.cfg"
  chmod 000 "${WORK}/secret.cfg"
  refused "a file this user may not read" "${WORK}/secret.cfg" "cannot be read"
fi

ESCAPED_NAME="${WORK}/$(printf 'esc\033[31mname').cfg"
printf '[read]\nrelative\n' > "$ESCAPED_NAME"
refused "a file whose name holds a control character, which is shown escaped" "$ESCAPED_NAME" "not an absolute path" "Found in" "esc\\E[31mname.cfg"
printf '[read]\n/usr\n' > "${WORK}/-dash.cfg"
cd "$WORK" || exit 1
accepted "a valid file whose name starts with a dash" "-dash.cfg"
cd - > /dev/null || exit 1

mkdir "${WORK}/fakebin"
printf '#!/bin/sh\nexit 1\n' > "${WORK}/fakebin/head"
chmod +x "${WORK}/fakebin/head"
RUN_PATH_PREFIX="${WORK}/fakebin"
refused "a tool the examination needs that fails, said in words and with no error of its own" "${WORK}/ok.cfg" "could not be examined"
RUN_PATH_PREFIX=""
CORE_E="${WORK}/core-e"
cp -R "$CORE_X" "$CORE_E"
mkdir "${CORE_E}/Base$(printf '\033[31m')bad.cfg"
RUN_CORE="$CORE_E"
refused "a base policy that is not a file, named with a control character, which is shown escaped" "${WORK}/ok.cfg" "matches Base*.cfg" "\\E[31mbad.cfg"
RUN_CORE="$CORE_X"

echo
echo "== a file that is not the text it should be =="
refused "a byte order mark before the first header" "$(cfg_text '\xef\xbb\xbf[read]\n/usr\n')" "byte order mark"
refused "a NUL byte inside a path" "$(cfg_text '[read]\n/us\0r\n')" "NUL byte"
refused "binary garbage, shown as text it can be read as" "$(cfg_text '\x00\x01\xff\xfe\n')" "NUL byte"
refused "high bytes with no NUL, shown escaped" "$(cfg_text '\xff\xfe\n[read]\n')" "appears before any [section] header"
refused "Windows line endings, on the first line that has one" "$(cfg_text '[read]\r\n/usr\r\n')" "carriage return" "line 1"
refused "a carriage return on a later line only" "$(cfg_text '[read]\n/usr\r\n')" "carriage return" "line 2"
accepted "no newline after the last line" "$(cfg_text '[read]\n/usr')"
accepted "an empty file" "$(cfg_text '')"
accepted "comments and blank lines only" "$(cfg_text '# a policy\n\n   \n')"
accepted "a tab before a header and a comment after it" "$(cfg_text '\t[read] # the readable paths\n/usr # the toolchain\n')"
accepted "the same section twice" "$(cfg_text '[read]\n/usr\n[read]\n/etc\n')"

echo
echo "== the shape of a file, and where the message says the fault is =="
refused "a path before any header" "$(cfg_text '/usr\n')" "appears before any [section] header" "line 1"
refused "a path after comments and blanks, before any header" "$(cfg_text '# one\n\n/usr\n')" "line 3"
refused "an unknown section names the sections there are" "$(cfg_text '[read]\n/usr\n[network]\nallow 1.2.3.4:80\n')" "unknown section 'network'" "line 3" "[connect]"
refused "a header that never closes" "$(cfg_text '[read\n/usr\n')" "appears before any [section] header" "line 1"
refused "an empty header" "$(cfg_text '[]\n')" "appears before any [section] header"
refused "a header in capitals" "$(cfg_text '[READ]\n/usr\n')" "unknown section" "line 1"
refused "a header with a space inside" "$(cfg_text '[read ]\n/usr\n')" "unknown section"
refused "the message names the file" "$(cfg_text '[limits]\ncolour=5\n')" "cfg." "line 2"

echo
echo "== a path that is not absolute =="
for section in read execute write create delete create-ipc create-symlink restructure; do
  refused "[${section}] a name relative to a directory" "$(cfg_text "[${section}]\nrelative/path\n")" "not an absolute path" "[${section}]" "line 2"
done
# The tilde is the case: a policy line that starts with one must stay a tilde, which the parser does not expand.
# shellcheck disable=SC2088
for path in "./x" "../x" '~/x' '$HOME' '"/usr/bin"' "'/usr/bin'" "-rf" "r /usr/bin" "usr" "."; do
  refused "[read] ${path}" "$(cfg_text "[read]\n%s\n" "$path")" "not an absolute path" "Write the whole path from /"
done
accepted "an absolute path with .. in it" "$(cfg_text '[read]\n/usr/../etc\n')"
accepted "an absolute path with a doubled and a trailing slash" "$(cfg_text '[read]\n/usr//bin/\n')"
mkdir -p "${WORK}/dir with space" "${WORK}/odd[name"
accepted "an absolute path with a space in it that exists" "$(cfg_text '[read]\n%s\n' "${WORK}/dir with space")"

echo
echo "== a wildcard in a path =="
refused "a relative path with a wildcard is first of all not absolute" "$(cfg_text '[read]\nrelative/*\n')" "not an absolute path"
CORE_W="${WORK}/core-w"
cp -R "$CORE_X" "$CORE_W"
printf '[read]\n/usr\n/usr/b*n\n' > "${CORE_W}/BaseTest.cfg"
RUN_CORE="$CORE_W"
refused "a wildcard in a base policy, which is exempt from the existence check only" "${WORK}/ok.cfg" "holds a wildcard character" "BaseTest.cfg', line 3"
RUN_CORE="$CORE_X"
for path in '/usr/b*n' '/usr/bin?' '/usr/[ab]' '/*' '/usr/lib/jvm/*/bin' "${WORK}/odd[name"; do
  refused "[read] ${path}" "$(cfg_text '[read]\n%s\n' "$path")" "holds a wildcard character" "Name the directory or the file itself" "line 2"
done
refused "[write] with a wildcard" "$(cfg_text '[write]\n/tmp/*\n')" "holds a wildcard character" "[write]"

echo
echo "== a path that does not exist =="
for section in read execute; do
  refused "[${section}] a path that does not exist" "$(cfg_text "[${section}]\n/nonexistent/where\n")" "does not exist on this system" "[${section}]" "line 2"
done
for section in write create delete create-ipc create-symlink restructure; do
  accepted "[${section}] a path that does not exist, which the filesystem layer creates" "$(cfg_text "[${section}]\n/nonexistent/where\n")"
done
refused "a path that exists after one that does not, at the line of the missing one" "$(cfg_text '[read]\n/usr\n/nonexistent/where\n/etc\n')" "line 3"
refused "a path under a file, which cannot exist" "$(cfg_text '[read]\n/etc/hostname/below\n')" "does not exist on this system"
ln -s "${WORK}/nowhere" "${WORK}/dangling-target"
refused "a link to nothing" "$(cfg_text '[read]\n%s\n' "${WORK}/dangling-target")" "does not exist on this system"
ln -s /usr "${WORK}/usr-link"
accepted "a link to something that exists" "$(cfg_text '[read]\n%s\n' "${WORK}/usr-link")"
RUN_CORE="$CORE_B"
accepted "a base policy that names a path this image lacks, which only exercise configurations may not" "${WORK}/ok.cfg"
accepted "and a loopback wildcard in the base beside an exercise rule that names a port" "$(cfg_text '[connect]\nallow 1.2.3.4:80\n')"
RUN_CORE="$CORE_X"

echo
echo "== digits that are not digits =="
for case in "[limits]\nnproc=٨\n|nproc" "[limits]\ntimeout=٨\n|timeout" "[limits]\ntimeout=８\n|timeout" "[limits]\ncpu=٥\n|cpu" \
  "[bind]\nallow ٨٠\n|bare port" "[bind]\nallow 9090\n[accept]\nexpose ٨٠٨٠ to 9090 from 127.0.0.1\n|not an 'expose" \
  "[connect]\nallow 1.2.3.4:٨٠\n|names no usable port" "[connect]\nallow 1.2.3.4:٨0\n|names no usable port" "[connect]\nallow 1.2.3.4:8٠\n|names no usable port" "[connect]\nallow 10.0.0.0/٨:80\n|prefix length"; do
  text="${case%|*}"
  fragment="${case##*|}"
  refused "${text//\\n/ / }" "$(cfg_text "$text")" "$fragment"
done

echo
echo "== numbers too long for the arithmetic =="
for case in "timeout=99999999999999999999|digits of seconds" "timeout=1000000000000000|digits of seconds" "timeout=18446744073709551616|digits of seconds" \
  "timeout=9999999999999999.000|digits of seconds" "nproc=1000000000000000000|more than 18 digits" "nproc=18446744073709551621|more than 18 digits" \
  "cpu=18446744073709551616|more than 18 digits" "nofile=99999999999999999999|more than 18 digits" "fsize_mb=1000000000000000000|more than 18 digits"; do
  refused "${case%%|*}, which would wrap to another number" "$(cfg_text "[limits]\n${case%%|*}\n")" "${case##*|}" "Write 0 to switch" "line 2"
done
for value in "timeout=999999999999999.999" "timeout=999999999999999" "timeout=000000000000000000000005" "nproc=999999999999999999" "cpu=000000000000000000000007" "timeout=5.250"; do
  accepted "${value}" "$(cfg_text "[limits]\n${value}\n")"
done

echo
echo "== a line that is not what its section takes =="
refused "[connect] without the word allow" "$(cfg_text '[connect]\ndeny 1.2.3.4:80\n')" "not an 'allow <host>[:<port>] [udp|tcp]' line" "line 2"
refused "[connect] with a bracket that does not close" "$(cfg_text '[connect]\nallow [::1\n')" "opens a bracket it does not close" "line 2"
refused "[connect] with a port that is not one" "$(cfg_text '[connect]\nallow 1.2.3.4:80;\n')" "names no usable port" "line 2"
refused "[connect] with a wildcard host name" "$(cfg_text '[connect]\nallow *.example.com:443\n')" "wildcard host name" "line 2"
refused "[connect] with a port above the highest" "$(cfg_text '[connect]\nallow 1.2.3.4:70000\n')" "names no usable port" "line 2"
refused "[bind] with a port above the highest" "$(cfg_text '[bind]\nallow 70000\n')" "names no usable port" "line 2"
accepted "[bind] with port 0, which asks the kernel for one" "$(cfg_text '[bind]\nallow 0\n')"
refused "[bind] with port 00" "$(cfg_text '[bind]\nallow 00\n')" "names no usable port" "line 2"
refused "[bind] with an address" "$(cfg_text '[bind]\nallow 127.0.0.1:80\n')" "not a bare port" "line 2"
refused "[accept] without the shape" "$(cfg_text '[accept]\nexpose 8080\n')" "not an 'expose <public-port> to <backend-port> from" "line 2"
refused "[limits] with a key that is no limit" "$(cfg_text '[limits]\ncolour=5\n')" "not a known limit" "line 2"
refused "[limits] with a value that is not a number" "$(cfg_text '[limits]\nnproc=abc\n')" "must be a non-negative whole number" "line 2"
refused "[limits] with a timeout in the wrong spelling" "$(cfg_text '[limits]\ntimeout=5.5\n')" "exactly three decimals" "line 2"
accepted "a loopback rule without a port beside a rule with one, which the guard alone then enforces" "$(cfg_text '[connect]\nallow 127.0.0.1:*\nallow 1.2.3.4:80\n')"
for line in 'allow localhost' 'allow 127.0.0.1' 'allow 127.9.9.9' 'allow 127.0.0.1/32' 'allow [::1]' 'allow ::1' 'allow 0:0:0:0:0:0:0:1' 'allow [::ffff:127.0.0.1]' 'allow localhost udp'; do
  accepted "a rule that names a single loopback address and no port: ${line}" "$(cfg_text '[connect]\n%s\n' "$line")"
done
for line in 'allow 127.0.0.1/1' 'allow 127.0.0.0/8' 'allow 127.0.0.1/31' 'allow 127.evil.example' 'allow 127.evil.example udp' 'allow 128.0.0.1' 'allow [::ffff:128.0.0.1]' 'allow [::1/64]' 'allow example.org' 'allow *'; do
  refused "a rule that names ${line#allow } and no port, which is not a single loopback address" "$(cfg_text '[connect]\n%s\n' "$line")" "and no port, and only loopback may name no port" "line 2"
done
accepted "a range that starts like loopback with a concrete port" "$(cfg_text '[connect]\nallow 127.0.0.1/1:8080\nallow 127.evil.example:443\n')"

echo
echo "== an Ares 2 policy that is not the text it should be =="
# The same file-level refusals for a name ending in .yaml, which the Ares 2 reader takes, with the same
# words. The control is a well-formed policy under a programming language configuration of this core.
mkdir -p "${CORE_X}/language-configurations"
printf '[base]\nBaseTest.cfg\n' > "${CORE_X}/language-configurations/TEST_CONFIGURATION.cfg"
ARES_POLICY='thisPolicyFileCompliesToThePolicyVersion: 1\nregardingTheSupervisedCode:\n  theFollowingProgrammingLanguageConfigurationIsUsed: TEST_CONFIGURATION\n  theFollowingClassesAreTestClasses: []\n  theFollowingResourceAccessesArePermitted:\n    regardingFileSystemInteractions: []\n    regardingNetworkConnections: []\n    regardingCommandExecutions: []\n    regardingThreadCreations: []\n    regardingPackageImports: []\n    regardingTimeouts: []\n'
# yaml_text FORMAT [ARGUMENT...]: as cfg_text, into a file whose name ends in .yaml.
# shellcheck disable=SC2059
yaml_text() {
  local file
  file="$(mktemp --suffix=.yaml "${WORK}/policy.XXXXXX")"
  printf -- "$@" > "$file"
  printf '%s' "$file"
}
accepted "a well-formed Ares 2 policy" "$(yaml_text "$ARES_POLICY")"
refused "an Ares 2 policy that names nothing" "${WORK}/missing.yaml" "does not exist" "missing.yaml"
if (( $(id -u) == 0 )); then
  skip "an Ares 2 policy this user may not read" "running as root, which reads every file"
else
  SECRET_YAML="$(yaml_text "$ARES_POLICY")"
  chmod 000 "$SECRET_YAML"
  refused "an Ares 2 policy this user may not read" "$SECRET_YAML" "cannot be read"
fi
mkdir "${WORK}/dir.yaml"
refused "an Ares 2 policy that is a directory" "${WORK}/dir.yaml" "is a directory"
refused "an Ares 2 policy with a byte order mark" "$(yaml_text "\xef\xbb\xbf${ARES_POLICY}")" "byte order mark"
refused "an Ares 2 policy with a NUL byte" "$(yaml_text "${ARES_POLICY}# \0\n")" "NUL byte"
refused "an Ares 2 policy with Windows line endings" "$(yaml_text 'thisPolicyFileCompliesToThePolicyVersion: 1\r\n')" "carriage return" "line 1"
refused "an Ares 2 policy with a byte that is not UTF-8, shown escaped" "$(yaml_text "${ARES_POLICY}# \xff\n")" "not valid UTF-8" "line 12"
refused "an Ares 2 policy with a tab" "$(yaml_text "${ARES_POLICY}\t# x\n")" "tab character" "line 12"
refused "an Ares 2 policy with an unknown configuration" "$(yaml_text "${ARES_POLICY//TEST_CONFIGURATION/OTHER_CONFIGURATION}")" "has no file" "line 3"

finish
