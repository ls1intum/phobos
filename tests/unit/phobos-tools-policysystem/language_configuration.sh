#!/usr/bin/env bash
# How a programming language configuration is read: the base policies it names and how each of its
# placeholders is determined. This file is the one place a programming language enters Phobos, so
# the loader must accept exactly the three generic primitives and the two sections, determine each
# value only from the environment and the PATH of the process that loads it, and refuse everything
# else with the file and the line. This suite pins both directions.
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
CONFIGURATIONS="${HOME_DIR}/language-configurations"
mkdir -p "${CONFIGURATIONS}/bases" "${WORK}/opt/tool/bin" "${WORK}/links" "${WORK}/bin" "${WORK}/srv" "${WORK}/cwd" "${WORK}/outside"
: > "${HOME_DIR}/BaseLanguage-x.cfg"
: > "${CONFIGURATIONS}/bases/BaseLanguage-y.cfg"
: > "${WORK}/outside/BaseLanguage-z.cfg"
ln -s "${WORK}/outside/BaseLanguage-z.cfg" "${HOME_DIR}/BaseLanguage-escape.cfg"
printf '#!/bin/sh\nexit 0\n' > "${WORK}/opt/tool/bin/tool"
chmod +x "${WORK}/opt/tool/bin/tool"
ln -s ../opt/tool/bin/tool "${WORK}/links/tool"
ln -s "${WORK}/links/tool" "${WORK}/bin/tool"
cp "${WORK}/opt/tool/bin/tool" "${WORK}/cwd/onlyhere"
# A shell variable that is not exported is not part of the environment, so no placeholder may be
# determined from it. It is set and never read here on purpose: the loader must not read it either.
# shellcheck disable=SC2034
PHOBOS_TEST_SHELL_ONLY="${WORK}/srv"

# Writes its standard input as the configuration of that name, then loads it in a subshell whose
# PATH starts with the fake tool's directory and whose current directory is ${WORK}/cwd, and prints
# the bases and the placeholders it determined, or "<status>|<message>" when the loader refuses.
load_result() {
  local name="$1"
  local message
  cat > "${CONFIGURATIONS}/${name}.cfg"
  message="$( (cd "${WORK}/cwd" && PATH="${WORK}/bin:${PATH}" && load_language_configuration "$name" "$HOME_DIR" \
    && printf 'base %s\n' "${LANGUAGE_CONFIGURATION_BASES[@]}" \
    && for key in "${!LANGUAGE_CONFIGURATION_PLACEHOLDERS[@]}"; do printf 'placeholder %s=%s\n' "$key" "${LANGUAGE_CONFIGURATION_PLACEHOLDERS[$key]}"; done | sort) 2>&1)"
  local status=$?
  if (( status == 0 )); then printf '%s' "$message"; else printf '%s|%s' "$status" "$message"; fi
}

echo "== accepted =="
expected="base ${HOME_DIR}/BaseLanguage-x.cfg
base ${CONFIGURATIONS}/bases/BaseLanguage-y.cfg
placeholder fallback.dir=${WORK}/srv
placeholder fixed.dir=${WORK}/srv
placeholder home.dir=${WORK}/home
placeholder tool.home=${WORK}/opt/tool"
actual="$(HOME="${WORK}/home" PHOBOS_TEST_UNSET="" load_result GOOD_CONFIGURATION <<EOF
# a comment
[base]
BaseLanguage-x.cfg
bases/BaseLanguage-y.cfg   # a base under language-configurations/

[placeholders]
tool.home     = command-ancestor tool 2
home.dir      = environment HOME
fallback.dir  = environment PHOBOS_TEST_UNSET ${WORK}/srv
fixed.dir     = fixed ${WORK}/srv
EOF
)"
check "both kinds of [base] entry, and each primitive, a chain of symbolic links and a fallback for an empty variable included" "$expected" "$actual"

if language_configuration_exists GOOD_CONFIGURATION "$HOME_DIR"; then ok "an existing configuration is found"; else bad "an existing configuration is found" "found" "not found"; fi
if language_configuration_exists MISSING_CONFIGURATION "$HOME_DIR"; then bad "a missing configuration is not found" "not found" "found"; else ok "a missing configuration is not found"; fi
if language_configuration_exists "../home/language-configurations/GOOD_CONFIGURATION" "$HOME_DIR"; then bad "a name that is a path is not found" "not found" "found"; else ok "a name that is a path is not found"; fi

echo "== refused =="
for case in \
  '[base]\nBaseLanguage-x.cfg\n[connect]\nallow localhost udp|unknown section' \
  'BaseLanguage-x.cfg|before any [section]' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = guess x|unknown primitive' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = command-ancestor missingtool 2|found no command' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = command-ancestor onlyhere 1|found no command' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = command-ancestor tool 0|levels' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = command-ancestor ../bin/tool 2|command name' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = command-ancestor tool 20|levels above it' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = fixed /bin/sh|not an existing directory' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = environment PHOBOS_TEST_SHELL_ONLY|cannot be determined' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = fixed srv|absolute' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = fixed /nonexistent/dir|not an existing directory' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = environment PHOBOS_TEST_UNSET|cannot be determined' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = environment PHOBOS_TEST_UNSET relative/dir|absolute' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = environment 1BAD|variable name' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = fixed /tmp\na = fixed /tmp|twice' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\nPROJECT_ROOT = fixed /tmp|determined by Phobos' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\nbad name = fixed /tmp|placeholder line' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = fixed /tmp extra|takes one' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = environment|takes a variable' \
  '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = command-ancestor tool|takes a command' \
  '[base]\n../BaseLanguage-x.cfg|..' \
  '[base]\nbases/../../BaseLanguage-x.cfg|..' \
  '[base]\n/etc/passwd|absolute' \
  '[base]\nBaseLanguage-missing.cfg|does not exist' \
  '[base]\nbases/BaseLanguage-missing.cfg|does not exist' \
  '[base]\nBaseLanguage-escape.cfg|leads out of' \
  '[base]\nBaseLanguage-x.cfg\r|carriage return'; do
  text="${case%|*}"
  needle="${case##*|}"
  result="$(printf '%b\n' "$text" | PHOBOS_TEST_UNSET="" load_result REFUSED_CONFIGURATION)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"${needle}"* && "${result#*|}" == *"REFUSED_CONFIGURATION.cfg', line "* ]]; then
    ok "refused, saying '${needle}', with file and line: ${text}"
  else
    bad "refused, saying '${needle}', with file and line: ${text}" "status ${PHB_EPOLICY}" "${result}"
  fi
done
result="$(printf '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = environment PHOBOS_TEST_NEWLINE\n' | PHOBOS_TEST_NEWLINE="${WORK}/srv"$'\n' load_result NEWLINE_CONFIGURATION)"
if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"control character"* && "${result#*|}" == *"NEWLINE_CONFIGURATION.cfg', line 4"* ]]; then
  ok "a variable whose value ends in a newline is refused, not read without it"
else
  bad "a variable whose value ends in a newline is refused, not read without it" "status ${PHB_EPOLICY}" "${result}"
fi

for entry in "." "" "cwd-relative"; do
  mkdir -p "${WORK}/cwd/cwd-relative"
  cp "${WORK}/opt/tool/bin/tool" "${WORK}/cwd/cwd-relative/onlyhere"
  result="$(printf '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = command-ancestor onlyhere 1\n' | PATH="${entry}:${PATH}" load_result RELATIVE_PATH_CONFIGURATION)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"found no command 'onlyhere' on the PATH"* ]]; then
    ok "a command reachable only through the relative PATH entry '${entry}' is not used"
  else
    bad "a command reachable only through the relative PATH entry '${entry}' is not used" "status ${PHB_EPOLICY}" "${result}"
  fi
done

mkdir -p "${WORK}/tools"
for tool in head od tr wc realpath dirname; do
  ln -s "$(type -P "$tool")" "${WORK}/tools/${tool}"
done
printf '[base]\nBaseLanguage-x.cfg\n[placeholders]\na = environment HOME /tmp\n' > "${CONFIGURATIONS}/NO_PRINTENV_CONFIGURATION.cfg"
if result="$( (PATH="${WORK}/tools" load_language_configuration NO_PRINTENV_CONFIGURATION "$HOME_DIR") 2>&1)"; then status=0; else status=$?; fi
if (( status == PHB_ERUNTIME )) && [[ "$result" == *"printenv could not be run"* ]]; then
  ok "an environment that cannot be read ends the run instead of falling back"
else
  bad "an environment that cannot be read ends the run instead of falling back" "status ${PHB_ERUNTIME}" "${status}|${result}"
fi

result="$(printf '[placeholders]\na = fixed /tmp\n' | load_result NO_BASE_CONFIGURATION)"
if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"names no base policy"* && "${result#*|}" == *"NO_BASE_CONFIGURATION.cfg'"* ]]; then
  ok "a configuration that names no base is refused, naming the file"
else
  bad "a configuration that names no base is refused, naming the file" "status ${PHB_EPOLICY}" "${result}"
fi
for bytes in '\xef\xbb\xbf[base]\nBaseLanguage-x.cfg\n' '[base]\nBaseLanguage-x.cfg\x00\n'; do
  result="$(printf '%b' "$bytes" | load_result BINARY_CONFIGURATION)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" ]]; then ok "refused: ${bytes}"; else bad "refused: ${bytes}" "status ${PHB_EPOLICY}" "${result}"; fi
done

if result="$( (load_language_configuration MISSING_CONFIGURATION "$HOME_DIR") 2>&1)"; then status=0; else status=$?; fi
if (( status == PHB_EPOLICY )) && [[ "$result" == *"has no file 'language-configurations/MISSING_CONFIGURATION.cfg' beside phobos-policysystem.sh, so Phobos does not know which base policy it runs under"* ]]; then
  ok "a configuration with no file is refused, saying so"
else
  bad "a configuration with no file is refused, saying so" "status ${PHB_EPOLICY}" "${status}|${result}"
fi
if result="$( (load_language_configuration "../x" "$HOME_DIR") 2>&1)"; then status=0; else status=$?; fi
if (( status == PHB_EPOLICY )) && [[ "$result" == *"is not the name of a programming language configuration"* ]]; then
  ok "a configuration name that is not a name is refused"
else
  bad "a configuration name that is not a name is refused" "status ${PHB_EPOLICY}" "${status}|${result}"
fi

echo "== the password database =="
# The home directory the password database holds for this user, read the way the JVM reads
# user.home. Each case changes HOME, so a value read from HOME would show.
REAL_HOME="$(getent passwd "$UID" | cut -d: -f6)"
result="$(printf '[base]\nBaseLanguage-x.cfg\n[placeholders]\nuser.home = password-database home\n' | HOME="${WORK}/srv" load_result PASSWORD_CONFIGURATION)"
check "password-database home gives the password database's home directory, not HOME" "base ${HOME_DIR}/BaseLanguage-x.cfg
placeholder user.home=${REAL_HOME}" "$result"

# A stand-in getent that answers for the uid it is asked about as PHOBOS_TEST_GETENT says, and fails
# with status 3 when it is asked anything but "passwd <this uid>", which the loader turns into a
# runtime error, so a wrong question shows as a failed check.
mkdir -p "${WORK}/fakegetent"
cat > "${WORK}/fakegetent/getent" <<'GETENT'
#!/bin/sh
[ "$1" = passwd ] && [ "$2" = "$(id -u)" ] || exit 3
case "${PHOBOS_TEST_GETENT}" in
  entry) printf 'tester:x:%s:0:Test User:%s:/bin/sh\n' "$2" "${PHOBOS_TEST_GETENT_HOME}" ;;
  missing) exit 2 ;;
  empty) printf 'tester:x:%s:0:Test User::/bin/sh\n' "$2" ;;
  relative) printf 'tester:x:%s:0:Test User:home/tester:/bin/sh\n' "$2" ;;
  nonexistent) printf 'tester:x:%s:0:Test User:/nonexistent:/bin/sh\n' "$2" ;;
  control) printf 'tester:x:%s:0:Test User:/tmp\001x:/bin/sh\n' "$2" ;;
  newline) printf 'tester:x:%s:0:Test User:/tmp\n:/bin/sh\n' "$2" ;;
  short) printf 'tester:x:%s\n' "$2" ;;
  broken) exit 1 ;;
esac
GETENT
chmod +x "${WORK}/fakegetent/getent"
result="$(printf '[base]\nBaseLanguage-x.cfg\n[placeholders]\nuser.home = password-database home\n' | PATH="${WORK}/fakegetent:${PATH}" PHOBOS_TEST_GETENT=entry PHOBOS_TEST_GETENT_HOME="${WORK}/srv" HOME=/tmp load_result PASSWORD_CONFIGURATION)"
check "the home field of the entry for this uid is the value" "base ${HOME_DIR}/BaseLanguage-x.cfg
placeholder user.home=${WORK}/srv" "$result"
for case in 'missing|found no entry for the uid' 'empty|empty home field' 'relative|not an absolute path' \
  'nonexistent|not an existing directory' 'control|control character' 'newline|control character' \
  'short|not seven colon-separated fields'; do
  mode="${case%%|*}"
  needle="${case#*|}"
  result="$(printf '[base]\nBaseLanguage-x.cfg\n[placeholders]\nuser.home = password-database home\n' | PATH="${WORK}/fakegetent:${PATH}" PHOBOS_TEST_GETENT="$mode" load_result PASSWORD_CONFIGURATION)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"${needle}"* && "${result#*|}" == *"PASSWORD_CONFIGURATION.cfg', line 4"* ]]; then
    ok "a password database entry that is ${mode} is refused, saying '${needle}', with file and line"
  else
    bad "a password database entry that is ${mode} is refused, saying '${needle}', with file and line" "status ${PHB_EPOLICY}" "${result}"
  fi
done
for written in 'password-database' 'password-database shell' 'password-database home extra'; do
  result="$(printf '[base]\nBaseLanguage-x.cfg\n[placeholders]\nuser.home = %s\n' "$written" | load_result PASSWORD_CONFIGURATION)"
  if [[ "${result%%|*}" == "${PHB_EPOLICY}" && "${result#*|}" == *"takes the one field it reads"* && "${result#*|}" == *"line 4"* ]]; then
    ok "refused, with file and line: ${written}"
  else
    bad "refused, with file and line: ${written}" "status ${PHB_EPOLICY}" "${result}"
  fi
done
printf '[base]\nBaseLanguage-x.cfg\n[placeholders]\nuser.home = password-database home\n' > "${CONFIGURATIONS}/BROKEN_GETENT_CONFIGURATION.cfg"
if result="$( (PATH="${WORK}/fakegetent:${PATH}" PHOBOS_TEST_GETENT=broken load_language_configuration BROKEN_GETENT_CONFIGURATION "$HOME_DIR") 2>&1)"; then status=0; else status=$?; fi
if (( status == PHB_ERUNTIME )) && [[ "$result" == *"getent could not be run"* ]]; then
  ok "a password database that cannot be read ends the run instead of being taken for no entry"
else
  bad "a password database that cannot be read ends the run instead of being taken for no entry" "status ${PHB_ERUNTIME}" "${status}|${result}"
fi

echo "== the shipped configurations =="
for file in "${CORE}"/config/language-configurations/*.cfg; do
  name="$(basename "$file" .cfg)"
  result="$( (PATH="${WORK}/bin:${PATH}"
    mkdir -p "${WORK}/shipped/${name}/language-configurations" "${WORK}/shipped/${name}/jdk/bin"
    cp "${CORE}/config/"Base*.cfg "${WORK}/shipped/${name}/"
    cp "$file" "${WORK}/shipped/${name}/language-configurations/"
    printf '#!/bin/sh\nexit 0\n' > "${WORK}/shipped/${name}/jdk/bin/java"
    chmod +x "${WORK}/shipped/${name}/jdk/bin/java"
    PATH="${WORK}/shipped/${name}/jdk/bin:${PATH}" HOME="${WORK}/home" TMPDIR="" load_language_configuration "$name" "${WORK}/shipped/${name}" \
      && printf '%s ' "${LANGUAGE_CONFIGURATION_BASES[@]##*/}" "${#LANGUAGE_CONFIGURATION_PLACEHOLDERS[@]}" "${LANGUAGE_CONFIGURATION_PLACEHOLDERS[user.home]}") 2>&1)"
  check "${name} loads, names its base and determines its placeholders, user.home from the password database" "BaseLanguage-java.cfg 3 ${REAL_HOME} " "$result"
done

finish
