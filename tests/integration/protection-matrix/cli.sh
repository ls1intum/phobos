#!/usr/bin/env bash
# The command line of phobos.sh and the policy files it reads: the manual, usage errors, the command's
# arguments, streams, status and environment, the override options, the tail flags and the odd policy files.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${PM_HERE}/lib.sh"
pm_setup || finish
trap pm_restore EXIT
PM_ABI="$(pm_abi)"
P="$PM/bin/pprobe"
cd "$PM/work" || exit 1
chmod 0777 "$PM/rw" "$PM/out"
echo "  landlock ABI ${PM_ABI}"

c_ro="$(cfg ro <<EOF2
[read]
$PM/ro
EOF2
)"
# The run's output with the start marker removed, for comparing a protected run with a direct one.
payload() {
  grep -v '^START$' "$1"
}
# Runs phobos.sh with standard input taken from a file, since run_pm gives it none.
run_pm_stdin() {
  local input="$1"
  shift
  PM_OUT="$PM/out/last.out"
  PM_ERR="$PM/out/last.err"
  timeout --kill-after=5 "$WATCHDOG_SECONDS" phobos.sh --tail-flags-file "$PM/tail.flags" "$@" < "$input" > "$PM_OUT" 2> "$PM_ERR"
  PM_STATUS=$?
}
# A run that must not start the command: not 0, no start marker, and the status named when one is expected.
refused_run() {
  local title="$1"
  local expected="$2"
  if grep -q '^START' "$PM_OUT"; then
    bad "$title" "the command started: $(pm_describe)"
  elif [[ -n "$expected" ]] && (( PM_STATUS != expected )); then
    bad "$title" "expected status ${expected}: $(pm_describe)"
  elif (( PM_STATUS == 0 )); then
    bad "$title" "ended with status 0: $(pm_describe)"
  else
    ok "$title"
  fi
}

echo
echo "== the manual and usage errors =="
run_pm --help
if (( PM_STATUS == 0 )) && grep -q '^USAGE' "$PM_OUT" && [[ ! -s "$PM_ERR" ]]; then ok "--help prints the manual on standard output and ends with status 0"; else bad "--help" "$(pm_describe)"; fi
manual_complete=1
for word in "--no-timeoutsystem-restriction" "--no-networksystem-restriction" "--no-resourcesystem-restriction" "--no-filesystem-restriction" "--no-restriction" "--config" "--debug" "--landlock-bin" "--connect-guard-bin" "--pgroup-lock-bin" "--timeout-bin" "--haproxy-bin" "--resolver" "--tail-flags-file" "--spec-parent" "PHB-EPOLICY" "PHB-ETIMEOUT" "PHB-ERUNTIME"; do
  grep -q -- "$word" "$PM_OUT" || { manual_complete=0; bad "the manual names ${word}" "it does not"; }
done
if (( manual_complete )); then ok "and the manual names every option and every exit status"; fi
run_pm -h
if (( PM_STATUS == 0 )) && grep -q '^USAGE' "$PM_OUT"; then ok "-h does the same"; else bad "-h" "$(pm_describe)"; fi
run_pm -nfr --help
if (( PM_STATUS == 0 )) && grep -q '^USAGE' "$PM_OUT"; then ok "--help after another option still prints the manual"; else bad "--help after another option" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- "$P" argv --help -h
if grep -q '^ARG\[0\]=<--help>' "$PM_OUT" && grep -q '^ARG\[1\]=<-h>' "$PM_OUT" && ! grep -q '^USAGE' "$PM_OUT"; then ok "--help after the command is the command's own argument"; else bad "--help after the command is an argument" "$(pm_describe)"; fi
usage_case() {
  local title="$1"
  shift
  PM_OUT="$PM/out/last.out"
  PM_ERR="$PM/out/last.err"
  timeout --kill-after=5 "$WATCHDOG_SECONDS" phobos.sh "$@" > "$PM_OUT" 2> "$PM_ERR" < /dev/null
  PM_STATUS=$?
  if (( PM_STATUS == PHB_EXIT_USAGE )) && ! grep -q '^START' "$PM_OUT" && grep -q '^USAGE' "$PM_ERR"; then ok "$title"; else bad "$title" "expected status ${PHB_EXIT_USAGE} and the manual on standard error: $(pm_describe)"; fi
}
usage_case "no arguments at all is a usage error that prints the manual on standard error"
usage_case "options with no command are a usage error" -nfr --config "$c_ro"
usage_case "an unknown option is refused rather than run as the command" -nnn --config "$c_ro" -- "$P" cwd
usage_case "a mistyped long option is refused" --no-network-restriction --config "$c_ro" -- "$P" cwd
usage_case "--config with no file after it is a usage error" --config
usage_case "--spec-parent with no value is a usage error" --spec-parent
usage_case "--resolver with no value is a usage error" --resolver
usage_case "--tail-flags-file with no value is a usage error" --tail-flags-file
usage_case "--landlock-bin with no value is a usage error" --landlock-bin
usage_case "only a double dash and no command is a usage error" --config "$c_ro" --

echo
echo "== the command's arguments arrive unchanged =="
arguments_equal() {
  local title="$1"
  shift
  run_direct "$P" argv "$@"
  payload "$PM_OUT" > "$PM/out/argv-direct.txt"
  run_pm --config "$c_ro" -- "$P" argv "$@"
  if grep -q '^START' "$PM_OUT" && cmp -s <(payload "$PM_OUT") "$PM/out/argv-direct.txt"; then ok "$title"; else bad "$title" "direct: $(tr '\n' '|' < "$PM/out/argv-direct.txt" | cut -c1-200) protected: $(pm_describe)"; fi
}
arguments_equal "words with spaces stay single arguments" "a b" "  leading and trailing  " $'tab\tinside'
arguments_equal "an empty argument stays an argument" "" "x" ""
arguments_equal "quotes, dollar signs, backticks and globs are not interpreted" "'q'" '"d"' '$HOME' '`id`' '*' '?' '[a]' '~' '$(id)'
arguments_equal "words that look like options stay arguments" -x --y -- --config -nr
arguments_equal "a newline inside an argument survives" "line one
line two"
arguments_equal "non-ASCII characters survive" "über" "日本語" "naïve"
arguments_equal "a backslash survives" 'a\b' '\n' '\\'
long_argument="$(head -c 100000 /dev/zero | tr '\0' 'x')"
run_direct "$P" argv "$long_argument"
direct_sum="$(payload "$PM_OUT" | cksum)"
run_pm --config "$c_ro" -- "$P" argv "$long_argument"
if [[ "$(payload "$PM_OUT" | cksum)" == "$direct_sum" ]]; then ok "an argument of 100000 characters arrives whole"; else bad "a 100000-character argument arrives whole" "$(pm_describe | cut -c1-200)"; fi
many=()
for index in $(seq 1 500); do
  many+=("argument-$index")
done
run_pm --config "$c_ro" -- "$P" argv "${many[@]}"
if [[ "$(grep -c '^ARG\[' "$PM_OUT")" == 500 ]] && grep -q '^ARG\[499\]=<argument-500>' "$PM_OUT"; then ok "five hundred arguments arrive in order"; else bad "five hundred arguments arrive" "$(pm_describe | cut -c1-200)"; fi
run_pm --config "$c_ro" -- "$P" argv -- inner
if grep -q '^ARG\[0\]=<-->' "$PM_OUT" && grep -q '^ARG\[1\]=<inner>' "$PM_OUT"; then ok "a second double dash after the command is the command's argument"; else bad "a second double dash is an argument" "$(pm_describe)"; fi

echo
echo "== standard streams =="
printf 'hello\0world\nno final newline' > "$PM/out/stdin-small"
run_pm_stdin "$PM/out/stdin-small" --config "$c_ro" -- "$P" cat
if [[ "$(tail -c +7 "$PM_OUT" | cksum)" == "$(cksum < "$PM/out/stdin-small")" ]]; then ok "standard input reaches the command, bytes and NUL included"; else bad "standard input reaches the command" "$(pm_describe)"; fi
head -c 1048576 /dev/urandom > "$PM/out/stdin-big"
run_pm_stdin "$PM/out/stdin-big" --config "$c_ro" -- "$P" cat
if [[ "$(tail -c +7 "$PM_OUT" | cksum)" == "$(cksum < "$PM/out/stdin-big")" ]]; then ok "a megabyte of random bytes through standard input comes back whole"; else bad "a megabyte through standard input" "$(wc -c < "$PM_OUT") bytes came back"; fi
run_pm --config "$c_ro" -- /bin/sh -c 'echo to-out; echo to-err >&2'
if grep -q '^to-out$' "$PM_OUT" && ! grep -q 'to-err' "$PM_OUT" && grep -q '^to-err$' "$PM_ERR"; then ok "the command's two streams stay separate"; else bad "the streams stay separate" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- /bin/sh -c 'echo "x: Permission denied" >&2; exit 0'
if (( PM_STATUS == 0 )) && grep -q 'Sandbox denials: network=0, filesystem=1. (PHB-EDENY)' "$PM_ERR"; then ok "a denial the command reports on standard error is counted and does not change its status"; else bad "a denial is counted" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- /bin/cat "$PM/none/secret.txt"
if (( PM_STATUS == 1 )) && grep -q 'Sandbox denials: network=0, filesystem=1' "$PM_ERR" && ! grep -q 'TOP-SECRET' "$PM_OUT" "$PM_ERR"; then ok "a real refusal is counted as one filesystem denial and the secret stays out of both streams"; else bad "a real refusal is counted" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- /bin/sh -c 'echo "a: Permission denied" >&2; echo "b: EACCES" >&2; echo "c: Network is unreachable" >&2; exit 3'
if (( PM_STATUS == 3 )) && grep -q 'Sandbox denials: network=1, filesystem=2' "$PM_ERR"; then ok "network and filesystem denials are counted apart, and the command's own status 3 passes through"; else bad "denials are counted apart" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- /bin/sh -c 'echo "Permission denied"; exit 0'
gap_case "a line the command prints on standard output is not counted as a denial" "README.md of this suite, limits found, observation 3" "$(holds_if bash -c "! grep -q 'Sandbox denials' '$PM_ERR'")"
run_pm --config "$c_ro" -- /bin/sh -c 'echo "I will say Permission denied by myself" >&2'
gap_case "but the count is only a hint: a command that prints those words on standard error itself is counted too" "README.md of this suite, limits found, observation 3" "$(holds_if bash -c "grep -q 'Sandbox denials: network=0, filesystem=1' '$PM_ERR'")"
run_pm --config "$c_ro" -- "$P" openfds
if grep -q '^OPENFDS 0$' "$PM_OUT"; then ok "the command inherits no descriptor above standard error from phobos.sh or its layers"; else bad "no leaked descriptors" "$(pm_describe)"; fi

echo
echo "== a command that cannot be started, and the command's own status =="
run_pm --config "$c_ro" -- /nonexistent/binary
refused_run "a command that does not exist is not started and the status is 127" 127
run_pm --config "$c_ro" -- "$PM/ro"
refused_run "a directory as the command is not started" ""
run_pm --config "$c_ro" -- "$PM/ro/data.txt"
refused_run "a file that is not executable is not started" ""
run_pm --config "$c_ro" -- "$P" exitwith 42
if (( PM_STATUS == 42 )); then ok "the command's own status 42 passes through"; else bad "status 42 passes through" "$(pm_describe)"; fi

echo
echo "== environment =="
FOO=bar run_pm --config "$c_ro" -- "$P" env FOO
if grep -q 'ENV FOO=bar' "$PM_OUT"; then ok "an ordinary variable reaches the command"; else bad "an ordinary variable reaches the command" "$(pm_describe)"; fi
PHB_DEBUG_ENABLED=1 run_pm --config "$c_ro" -- "$P" cwd
if ! grep -q '^\[phobos\]' "$PM_ERR"; then ok "debug output cannot be switched on from the environment"; else bad "debug stays off without --debug" "$(pm_describe)"; fi
run_pm --debug --config "$c_ro" -- "$P" cwd
if grep -q '^\[phobos\] policy: read.paths:' "$PM_ERR" && grep -q "^CWD " "$PM_OUT"; then ok "--debug prints the effective policy on standard error and leaves the command's output alone"; else bad "--debug prints the policy" "$(pm_describe)"; fi

echo
echo "== the override options =="
run_pm --config "$c_ro" --landlock-bin /nonexistent -- "$P" cwd
refused_run "a missing Landlock enforcer refuses the run rather than running unconfined" "$PHB_ERUNTIME"
run_pm --config "$c_ro" --connect-guard-bin /nonexistent -- "$P" cwd
refused_run "a missing connect guard refuses the run" "$PHB_ERUNTIME"
run_pm --config "$c_ro" --pgroup-lock-bin /nonexistent -- "$P" cwd
refused_run "a missing group lock refuses the run" "$PHB_ERUNTIME"
run_pm --config "$c_ro" --timeout-bin /nonexistent -- "$P" cwd
refused_run "a missing timeout tool refuses the run" ""
c_host="$(cfg hostrule <<EOF2
[connect]
allow example.org:443
EOF2
)"
run_pm --resolver 127.0.0.1:5353 --config "$c_host" --haproxy-bin /nonexistent -- "$P" cwd
refused_run "a missing egress broker refuses a run whose policy needs it" "$PHB_ERUNTIME"
run_pm --config "$c_ro" --haproxy-bin /nonexistent -- "$P" cwd
if grep -q '^START' "$PM_OUT" && (( PM_STATUS == 0 )); then ok "and a policy that needs no broker does not care that it is missing"; else bad "a missing broker does not matter without a host rule" "$(pm_describe)"; fi
run_pm -nnr --connect-guard-bin /nonexistent --config "$c_ro" -- "$P" cwd
if grep -q '^START' "$PM_OUT" && (( PM_STATUS == 0 )); then ok "the connect guard is not needed when the network layer is off"; else bad "no guard needed with the network layer off" "$(pm_describe)"; fi
run_pm -ntr --pgroup-lock-bin /nonexistent --timeout-bin /nonexistent --config "$c_ro" -- "$P" cwd
if grep -q '^START' "$PM_OUT" && (( PM_STATUS == 0 )); then ok "nor the timeout tool and the group lock when the timeout layer is off"; else bad "no timeout tool needed with the timeout layer off" "$(pm_describe)"; fi
run_pm -nfr -nnr --landlock-bin /nonexistent --config "$c_ro" -- "$P" cwd
if grep -q '^START' "$PM_OUT" && (( PM_STATUS == 0 )); then ok "nor the Landlock enforcer when the filesystem and network layers are both off"; else bad "no enforcer needed with both layers off" "$(pm_describe)"; fi

echo
echo "== the tail flags and the base policy =="
if (( PM_ABI < 10 )); then
  printf -- '--chdir %s/work\n--minimum-landlock-version 10\n' "$PM" > "$PM/strict.flags"
  run_pm --tail-flags-file "$PM/strict.flags" --config "$c_ro" -- "$P" cwd
  refused_run "a minimum Landlock version above what the kernel offers refuses the run before the command" 125
else
  skip "a minimum Landlock version above the kernel's refuses the run" "this kernel offers version ${PM_ABI}, so 10 is satisfied"
fi
printf -- '--chdir %s/work\n--minimum-landlock-version 99\n' "$PM" > "$PM/strict.flags"
run_pm --tail-flags-file "$PM/strict.flags" --config "$c_ro" -- "$P" cwd
refused_run "a minimum version no kernel can offer refuses every run" 125
run_pm --tail-flags-file "$PM/nonexistent.flags" --config "$c_ro" -- "$P" cwd
gap_case "a tail flags file that does not exist is ignored, so the minimum version in the real one is silently lost" "README.md of this suite, limits found, observation 1" "$(holds_if bash -c "grep -q '^START' '$PM_OUT' && [[ '$PM_STATUS' == 0 ]]")"
printf -- '--chdir %s\n' "$PM/ro" > "$PM/chdir.flags"
run_pm --tail-flags-file "$PM/chdir.flags" --config "$c_ro" -- "$P" cwd
if grep -q "^CWD $PM/ro\$" "$PM_OUT"; then ok "a tail flag --chdir moves the command's working directory"; else bad "--chdir in the tail flags" "$(pm_describe)"; fi
mv "${PHOBOS_HOME}/BaseLanguage-java.cfg" "$PM/base.moved"
run_pm --config "$c_ro" -- "$P" cwd
no_base_status="$PM_STATUS"
no_base_started="$(grep -c '^START' "$PM_OUT")"
no_base_message="$(grep -c 'no Base\*.cfg' "$PM_ERR")"
run_pm --no-restriction -- "$P" cwd
mv "$PM/base.moved" "${PHOBOS_HOME}/BaseLanguage-java.cfg"
if [[ "$no_base_status" == "$PHB_EPOLICY" && "$no_base_started" == 0 && "$no_base_message" -ge 1 ]]; then ok "with no base policy the run is refused rather than run unconfined"; else bad "with no base policy the run is refused" "status ${no_base_status}, started ${no_base_started}"; fi
if grep -q '^START' "$PM_OUT" && (( PM_STATUS == 0 )); then ok "--no-restriction needs no base policy, which is what makes it the escape hatch it says it is"; else bad "--no-restriction without a base policy" "$(pm_describe)"; fi

echo
echo "== policy files that are odd =="
: > "$PM/cfg/empty.cfg"
run_pm --config "$PM/cfg/empty.cfg" -- "$P" cwd
if (( PM_STATUS == 0 )) && grep -q '^START' "$PM_OUT"; then ok "an empty policy file adds nothing and is accepted"; else bad "an empty policy file" "$(pm_describe)"; fi
printf '# only a comment\n\n   \n' > "$PM/cfg/comments.cfg"
run_pm --config "$PM/cfg/comments.cfg" -- "$P" cwd
if (( PM_STATUS == 0 )) && grep -q '^START' "$PM_OUT"; then ok "a file of comments and blank lines is accepted"; else bad "a comment-only policy file" "$(pm_describe)"; fi
printf 'stray line\n[read]\n' > "$PM/cfg/before.cfg"
run_pm --config "$PM/cfg/before.cfg" -- "$P" cwd
refused_run "a line before the first section is refused" "$PHB_EPOLICY"
printf '[read]\n%s\n' "$PM/none" > "$PM/cfg/dup1.cfg"
printf '[read]\n%s\n[read]\n%s\n' "$PM/ro" "$PM/rw" > "$PM/cfg/dup2.cfg"
run_pm --config "$PM/cfg/dup2.cfg" -- /bin/sh -c "$P read $PM/ro/data.txt; $P read $PM/rw/data.txt"
if [[ "$(grep -c '^CONTENT' "$PM_OUT")" == 2 ]]; then ok "the same section twice in one file adds up"; else bad "the same section twice adds up" "$(pm_describe)"; fi
run_pm --config "$PM/cfg/dup1.cfg" --config "$PM/cfg/dup2.cfg" -- /bin/sh -c "$P read $PM/none/secret.txt; $P read $PM/ro/data.txt"
if [[ "$(grep -c '^CONTENT' "$PM_OUT")" == 2 ]]; then ok "several --config files add up, in any one of them"; else bad "several --config files add up" "$(pm_describe)"; fi
run_pm --config "$PM/cfg/dup2.cfg" -- "$P" read "$PM/none/secret.txt"
if op_failed_with open $DENIED_ERRNOS; then ok "and a later file never takes away what it did not name: the hidden directory stays hidden"; else bad "the hidden directory stays hidden" "$(pm_describe)"; fi
printf '[read]\n%s\n[write]\n%s\n' "$PM/rw" "$PM/rw" > "$PM/cfg/rwboth.cfg"
run_pm --config "$PM/cfg/rwboth.cfg" -- /bin/sh -c "$P read $PM/rw/data.txt; $P write $PM/rw/data.txt X"
if grep -q '^CONTENT' "$PM_OUT" && op_ok write; then ok "the same path under two rights holds both"; else bad "the same path under two rights" "$(pm_describe)"; fi
mkdir -p "$PM/ro dir"
printf 'SPACE\n' > "$PM/ro dir/f.txt"
printf '[read]\n%s/ro dir\n' "$PM" > "$PM/cfg/space.cfg"
run_pm --config "$PM/cfg/space.cfg" -- "$P" read "$PM/ro dir/f.txt"
if grep -q 'CONTENT SPACE' "$PM_OUT"; then ok "a path with a space in it is one path"; else bad "a path with a space" "$(pm_describe)"; fi
printf '[read]\n  \t%s/ro dir/   # trailing comment\n' "$PM" > "$PM/cfg/trim.cfg"
run_pm --config "$PM/cfg/trim.cfg" -- "$P" read "$PM/ro dir/f.txt"
if grep -q 'CONTENT SPACE' "$PM_OUT"; then ok "leading tabs, a trailing slash and a trailing comment do not change the path"; else bad "whitespace, slash and comment" "$(pm_describe)"; fi
printf '[read]\r\n%s\r\n' "$PM/ro" > "$PM/cfg/crlf.cfg"
run_pm --config "$PM/cfg/crlf.cfg" -- "$P" read "$PM/ro/data.txt"
if grep -q 'CONTENT READ-OK' "$PM_OUT"; then ok "a policy file with Windows line endings still grants its path, so the carriage return is not part of the path"; else bad "a CRLF policy file" "$(pm_describe)"; fi
printf '[read]\n%s/does-not-exist\n' "$PM" > "$PM/cfg/missing.cfg"
run_pm --config "$PM/cfg/missing.cfg" -- "$P" cwd
if (( PM_STATUS == 0 )); then ok "a path that does not exist is skipped, not an error, and grants nothing"; else bad "a missing path is skipped" "$(pm_describe)"; fi
ln -sfn "$PM/ro" "$PM/link-to-ro"
printf '[read]\n%s\n' "$PM/link-to-ro" > "$PM/cfg/symlink.cfg"
run_pm --config "$PM/cfg/symlink.cfg" -- "$P" read "$PM/ro/data.txt"
if grep -q 'CONTENT READ-OK' "$PM_OUT"; then ok "a symbolic link in a policy grants the directory it points to"; else bad "a symbolic link in a policy" "$(pm_describe)"; fi
printf '[read]\n%s/r*\n' "$PM" > "$PM/cfg/glob.cfg"
run_pm --config "$PM/cfg/glob.cfg" -- "$P" read "$PM/ro/data.txt"
if op_failed_with open $DENIED_ERRNOS; then ok "a star in a policy path is a literal name, not a pattern"; else bad "a star in a path is literal" "$(pm_describe)"; fi
printf '[read]\n%s/work/../ro\n' "$PM" > "$PM/cfg/dotdot.cfg"
run_pm --config "$PM/cfg/dotdot.cfg" -- "$P" read "$PM/ro/data.txt"
if grep -q 'CONTENT READ-OK' "$PM_OUT"; then ok "dot-dot segments in a policy path are resolved"; else bad "dot-dot segments" "$(pm_describe)"; fi
printf '[read]\nro\n' > "$PM/cfg/relative.cfg"
( cd "$PM" && run_pm --config "$PM/cfg/relative.cfg" -- "$P" read "$PM/ro/data.txt" )
from_parent_ok=$(grep -q 'CONTENT READ-OK' "$PM_OUT" && op_ok open; echo $?)
run_pm --config "$PM/cfg/relative.cfg" -- "$P" read "$PM/ro/data.txt"
from_work_denied=$(grep -q '^START' "$PM_OUT" && op_failed_with open $DENIED_ERRNOS; echo $?)
gap_case "a relative path in a policy is resolved against the directory phobos.sh runs in, so the same file grants a directory from one place and nothing from another" "README.md of this suite, limits found, observation 2" "$(( from_parent_ok == 0 && from_work_denied == 0 ? 0 : 1 ))"
mkdir -p "$PM/many"
many_cfg="$PM/cfg/many.cfg"
printf '[read]\n' > "$many_cfg"
for index in $(seq 1 400); do
  mkdir -p "$PM/many/d$index"
  printf 'MANY-%s\n' "$index" > "$PM/many/d$index/f.txt"
  printf '%s/many/d%s\n' "$PM" "$index" >> "$many_cfg"
done
run_pm --config "$many_cfg" -- /bin/sh -c "$P read $PM/many/d1/f.txt; $P read $PM/many/d400/f.txt; $P read $PM/many/d401/f.txt"
if grep -q 'CONTENT MANY-1' "$PM_OUT" && grep -q 'CONTENT MANY-400' "$PM_OUT"; then ok "four hundred policy paths are all applied, the first and the last alike"; else bad "four hundred policy paths" "$(pm_describe)"; fi

echo
echo "== the specification directory cannot be reached by the command =="
printf '[read]\n%s\n[write]\n/var/tmp\n' "$PM/ro" > "$PM/cfg/write-vartmp.cfg"
run_pm --config "$PM/cfg/write-vartmp.cfg" -- "$P" cwd
refused_run "a write path above the default specification parent refuses the run: the command could rewrite the connect policy" "$PHB_EPOLICY"
printf '[read]\n%s\n[create]\n%s\n' "$PM/ro" "$PM/rw" > "$PM/cfg/create-spec.cfg"
run_pm --spec-parent "$PM/rw" --config "$PM/cfg/create-spec.cfg" -- "$P" cwd
refused_run "a create path above a chosen specification parent refuses the run too" "$PHB_EPOLICY"
printf '[read]\n%s\n[delete]\n%s\n' "$PM/ro" "$PM/rw" > "$PM/cfg/delete-spec.cfg"
run_pm --spec-parent "$PM/rw" --config "$PM/cfg/delete-spec.cfg" -- "$P" cwd
refused_run "and so does a delete path" "$PHB_EPOLICY"
ln -sfn "$PM/rw" "$PM/rwlink"
printf '[read]\n%s\n[write]\n%s\n' "$PM/ro" "$PM/rw" > "$PM/cfg/write-rw.cfg"
run_pm --spec-parent "$PM/rwlink" --config "$PM/cfg/write-rw.cfg" -- "$P" cwd
refused_run "a symbolic link to the writable directory as the parent does not get round it" "$PHB_EPOLICY"
run_pm --spec-parent "$PM/rw2" --config "$PM/cfg/write-rw.cfg" -- "$P" cwd
if (( PM_STATUS == 0 )) && grep -q '^START' "$PM_OUT"; then ok "a specification parent outside every write path is accepted"; else bad "a specification parent outside the write paths" "$(pm_describe)"; fi
run_pm --spec-parent relative --config "$c_ro" -- "$P" cwd
refused_run "a relative specification parent is refused" "$PHB_EPOLICY"
run_pm --spec-parent "$PM/nonexistent" --config "$c_ro" -- "$P" cwd
refused_run "a specification parent that does not exist is refused" "$PHB_EPOLICY"

finish
