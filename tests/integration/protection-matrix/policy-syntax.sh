#!/usr/bin/env bash
# Every shape of a policy line the parser can be handed, judged through phobos.sh: what is accepted and starts the
# command, what is refused before the command with which status, and what a limit reads back as in the kernel.
# The neighbours are checked beside the refusals, so a parser that refuses everything cannot pass.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${PM_HERE}/lib.sh"
pm_setup || finish
trap pm_restore EXIT
PM_ABI="$(pm_abi)"
P="$PM/bin/pprobe"
cd "$PM/work" || exit 1
chmod 0777 "$PM/out"
echo "  landlock ABI ${PM_ABI}"

# policy BODY...: writes a policy of the lines given after a read grant for the probe, and prints its path.
policy() {
  {
    printf '[read]\n%s\n' "$PM/ro"
    printf '%s\n' "$@"
  } > "$PM/cfg/syntax.cfg"
  printf '%s\n' "$PM/cfg/syntax.cfg"
}
# started: whether the last run reached its command.
started() {
  grep -q '^START' "$PM_OUT"
}
# accepted TITLE LINES...: the policy is accepted and the command runs and ends with status 0.
accepted() {
  local title="$1"
  shift
  local config
  config="$(policy "$@")"
  run_pm --config "$config" -- "$P" cwd
  if started && (( PM_STATUS == 0 )); then ok "accepted: ${title}"; else bad "accepted: ${title}" "$(pm_describe)"; fi
}
# refused TITLE STATUS LINES...: the policy ends the run with that status before the command is reached.
refused() {
  local title="$1"
  local expected="$2"
  shift 2
  local config
  config="$(policy "$@")"
  run_pm --config "$config" -- "$P" cwd
  if ! started && (( PM_STATUS == expected )); then ok "refused with ${expected}: ${title}"; else bad "refused with ${expected}: ${title}" "$(pm_describe)"; fi
}
# The soft and hard value a resource read back as in the last run.
rlimit() {
  sed -n "s/^RLIMIT $1 soft=\\([0-9]*\\) hard=\\([0-9]*\\)/\\1 \\2/p" "$PM_OUT" | head -1
}
# reads_back TITLE RESOURCE EXPECTED LINES...: the limit lines are accepted and the kernel holds the value.
reads_back() {
  local title="$1"
  local resource="$2"
  local expected="$3"
  shift 3
  local config
  config="$(policy "$@")"
  run_pm --config "$config" -- "$P" getrlimit
  check "reads back: ${title}" "$expected" "$(rlimit "$resource")"
}
MB=$((1024 * 1024))

echo
echo "== [connect] lines that are accepted =="
for line in \
  "allow 127.0.0.1" "allow 127.0.0.1:80" "allow 127.0.0.1:65535" "allow  127.0.0.1:80" "allow 127.0.0.1:80 tcp" \
  "allow 10.0.0.0/8:80" "allow 127.0.0.1/32:80" "allow [::1]" "allow [::1]:80" "allow ::1" "allow [::]:80" \
  "allow [::ffff:127.0.0.1]:80" "allow localhost" "allow localhost:80" "allow *:80" \
  "allow 127.0.0.1:*"; do
  accepted "[connect] ${line}" "[connect]" "$line"
done

echo
echo "== [connect] lines that are refused as a policy error =="
for line in \
  "allow 127.0.0.1:0" "allow 127.0.0.1:65536" "allow 127.0.0.1:99999" "allow 127.0.0.1:-1" "allow 127.0.0.1:abc" \
  "allow 127.0.0.1:080" "allow 127.0.0.1:0x50" "allow :80" "allow" "ALLOW 127.0.0.1:80" "allow 127.0.0.1:80 TCP" \
  "allow 127.0.0.1:80 sctp" "allow 127.0.0.1:80 tcp extra" "allow ::1:80" "allow [::1" "allow *" "allow *:*" \
  "allow *.example.org" "allow ex*mple.org:80" "allow example.org" "allow 2001:db8::/32" \
  "allow 256.1.1.1:80" "allow 1.2.3:80" "allow 1.2.3.4.5:80" "allow 127.1:80" "allow 2130706433:80" "allow 01.2.3.4:80" \
  "allow 127.0.0.1/33:80" "allow 127.0.0.1/-1:80" "allow 127.0.0.1/abc:80" "allow 127.0.0.1/:80" "allow 0.0.0.0/0:80" \
  "allow [::/0]:80" "allow [::1/129]:80" "allow 127.0.0.1:" "allow [::1]:" "allow [::1::2]:80" "allow [fe80::1%eth0]:80" \
  "allow example.org/24:80"; do
  refused "[connect] ${line}" "$PHB_EPOLICY" "[connect]" "$line"
done

echo
echo "== [connect] host names need a resolver the run does not have =="
for line in "allow example.org:443" "allow example.org.:443" "allow -bad.example:80" "allow under_score.example:80" \
  "allow LOCALHOST:80" "allow 0x7f.1:80"; do
  refused "[connect] ${line}" "$PHB_ERUNTIME" "[connect]" "$line"
done
if (( PM_ABI >= 10 )); then
  accepted "[connect] allow 127.0.0.1:80 udp on a kernel with Landlock version 10" "[connect]" "allow 127.0.0.1:80 udp"
else
  refused "[connect] allow 127.0.0.1:80 udp below Landlock version 10, never left unenforced" 125 "[connect]" "allow 127.0.0.1:80 udp"
fi
accepted "a udp rule with no port, which the guard alone enforces" "[connect]" "allow 127.0.0.1 udp"

echo
echo "== [bind] lines =="
for line in "allow 8080" "allow 0" "allow 65535" "allow 8080 tcp" "allow 1" "allow 1023"; do
  accepted "[bind] ${line}" "[bind]" "$line"
done
accepted "[bind] the same port twice" "[bind]" "allow 80" "allow 80"
for line in "allow 65536" "allow 00" "allow 080" "allow -1" "allow 127.0.0.1:80" "allow 8080 UDP" "allow 8080 tcp udp" \
  "allow" "8080" "allow abc" "allow 8080:9090"; do
  refused "[bind] ${line}" "$PHB_EPOLICY" "[bind]" "$line"
done
if (( PM_ABI >= 10 )); then
  accepted "[bind] allow 8080 udp on a kernel with Landlock version 10" "[bind]" "allow 8080 udp"
else
  refused "[bind] allow 8080 udp below Landlock version 10, never left unenforced" 125 "[bind]" "allow 8080 udp"
fi

echo
echo "== [accept] lines =="
accepted "an exposed port in front of a bound backend" "[bind]" "allow 9090" "[accept]" "expose 8080 to 9090 from 127.0.0.1"
for source in "127.0.0.1, 10.0.0.0/8" "::1" "2001:db8::/32" "127.0.0.1,,10.0.0.1" "127.0.0.1/32" "0.0.0.0/0" "::/0" "fe80::1" \
  "0:0:0:0:0:0:0:1"; do
  accepted "[accept] from ${source}" "[bind]" "allow 9090" "[accept]" "expose 8080 to 9090 from ${source}"
done
accepted "[accept] with no source at all, which admits nobody" "[bind]" "allow 9090" "[accept]" "expose 8080 to 9090 from"
for source in "999.1.1.1" "10.0.0.0/33" "1.2.3.4/abc" "a:b:c"; do
  refused "[accept] from ${source}, which the inbound filter cannot read" "$PHB_ERUNTIME" "[bind]" "allow 9090" "[accept]" "expose 8080 to 9090 from ${source}"
done
for source in "127.0.0.1 10.0.0.1" "not-an-ip" "*"; do
  refused "[accept] from ${source}" "$PHB_EPOLICY" "[bind]" "allow 9090" "[accept]" "expose 8080 to 9090 from ${source}"
done
refused "[accept] with a backend that no [bind] row names" "$PHB_EPOLICY" "[accept]" "expose 8080 to 9090 from 127.0.0.1"
refused "[accept] with a second backend that no [bind] row names" "$PHB_EPOLICY" "[bind]" "allow 9090" "[accept]" "expose 8080 to 9090 from 127.0.0.1" "expose 8080 to 9091 from 127.0.0.1"
refused "[accept] with a public port that is also a [bind] port" "$PHB_EPOLICY" "[bind]" "allow 8080" "allow 9090" "[accept]" "expose 8080 to 9090 from 127.0.0.1"
refused "[accept] with a public port below 1024" "$PHB_EPOLICY" "[bind]" "allow 9090" "[accept]" "expose 80 to 9090 from 127.0.0.1"
refused "[accept] with a public port at 1000" "$PHB_EPOLICY" "[bind]" "allow 9090" "[accept]" "expose 1000 to 9090 from 127.0.0.1"
refused "[accept] with public port 0" "$PHB_EPOLICY" "[bind]" "allow 9090" "[accept]" "expose 0 to 9090 from 127.0.0.1"
refused "[accept] with backend port 0" "$PHB_EPOLICY" "[bind]" "allow 9090" "[accept]" "expose 8080 to 0 from 127.0.0.1"
refused "[accept] with public port 65536" "$PHB_EPOLICY" "[bind]" "allow 9090" "[accept]" "expose 65536 to 9090 from 127.0.0.1"
refused "[accept] with a leading zero in the port" "$PHB_EPOLICY" "[bind]" "allow 9090" "[accept]" "expose 08080 to 9090 from 127.0.0.1"
refused "[accept] with the keyword in capitals" "$PHB_EPOLICY" "[bind]" "allow 9090" "[accept]" "EXPOSE 8080 to 9090 from 127.0.0.1"
refused "[accept] without the word to" "$PHB_EPOLICY" "[bind]" "allow 9090" "[accept]" "expose 8080 9090 from 127.0.0.1"
refused "[accept] without the word from" "$PHB_EPOLICY" "[bind]" "allow 9090" "[accept]" "expose 8080 to 9090"

echo
echo "== [limits]: the timeout spelling =="
for value in 5 5.000 007 0 0.000 99999999999 999999999999999; do
  accepted "timeout=${value}" "[limits]" "timeout=${value}"
done
for value in 5.0 5.00 5.0000 .5 5. -5 +5 1e3 5s "" 1000000000000000 99999999999999999999 18446744073709551616; do
  refused "timeout=${value}" "$PHB_EPOLICY" "[limits]" "timeout=${value}"
done
accepted "spaces around the equals sign" "[limits]" "timeout = 5"
accepted "a leading space before the key" "[limits]" " timeout=5"
accepted "a trailing comment after the value" "[limits]" "timeout=5 # a comment"
accepted "the same key twice" "[limits]" "timeout=5" "timeout=10"
refused "the key in capitals" "$PHB_EPOLICY" "[limits]" "TIMEOUT=5"
refused "a key no limit has" "$PHB_EPOLICY" "[limits]" "colour=5"
refused "a value with no key" "$PHB_EPOLICY" "[limits]" "5"
run_pm_timed --config "$(policy "[limits]" "timeout=0.001")" -- "$P" sleep 20
if (( PM_STATUS == PHB_ETIMEOUT )) && (( PM_ELAPSED_MS < 15000 )); then ok "the smallest limit there is, 0.001 seconds, ends a sleeping command with the timeout status"; else bad "a limit of a millisecond ends the command" "status ${PM_STATUS} after ${PM_ELAPSED_MS} ms"; fi
run_pm_timed --config "$(policy "[limits]" "timeout=2")" -- "$P" sleep 5
if (( PM_STATUS == PHB_ETIMEOUT )); then ok "a limit of two seconds ends a command that sleeps five"; else bad "a limit of two seconds ends a sleep of five" "$(pm_describe)"; fi
run_pm_timed --config "$(policy "[limits]" "timeout=2" "timeout=0")" -- "$P" sleep 5
if (( PM_STATUS == 0 )) && grep -q SLEPT "$PM_OUT"; then ok "a zero beside that finite value in one file switches the limit off, and the same sleep runs to its end"; else bad "a zero beside a finite value" "$(pm_describe)"; fi

echo
echo "== [limits]: values read back from the kernel =="
reads_back "nofile=64" nofile "64 64" "[limits]" "nofile=64"
reads_back "nofile=0064, read in base ten" nofile "64 64" "[limits]" "nofile=0064"
reads_back "nofile=010, which is ten and not eight" nofile "10 10" "[limits]" "nofile=010"
reads_back "nofile=16" nofile "16 16" "[limits]" "nofile=16"
hard_nofile="$(ulimit -Hn)"
if [[ "$hard_nofile" =~ ^[0-9]+$ ]] && (( hard_nofile >= 64 )); then
  reads_back "nofile equal to the container's own hard limit, ${hard_nofile}" nofile "${hard_nofile} ${hard_nofile}" "[limits]" "nofile=${hard_nofile}"
else
  skip "nofile equal to the container's own hard limit" "the container reports ${hard_nofile}, which is not a number to name"
fi
reads_back "fsize_mb=1" fsize "$((1 * MB)) $((1 * MB))" "[limits]" "fsize_mb=1"
reads_back "fsize_mb=010, which is ten megabytes" fsize "$((10 * MB)) $((10 * MB))" "[limits]" "fsize_mb=010"
reads_back "fsize_mb=1024" fsize "$((1024 * MB)) $((1024 * MB))" "[limits]" "fsize_mb=1024"
reads_back "cpu=1" cpu "1 1" "[limits]" "cpu=1"
reads_back "cpu=010, which is ten seconds" cpu "10 10" "[limits]" "cpu=010"
reads_back "cpu=4294967295" cpu "4294967295 4294967295" "[limits]" "cpu=4294967295"
reads_back "nproc=1" nproc "1 1" "[limits]" "nproc=1"
reads_back "nproc=0100, which is one hundred" nproc "100 100" "[limits]" "nproc=0100"
reads_back "mem_mb=512" as "$((512 * MB)) $((512 * MB))" "[limits]" "mem_mb=512"
reads_back "mem_mb=0512" as "$((512 * MB)) $((512 * MB))" "[limits]" "mem_mb=0512"
reads_back "mem_mb=4096" as "$((4096 * MB)) $((4096 * MB))" "[limits]" "mem_mb=4096"
reads_back "two keys of different limits in one file" nofile "20 20" "[limits]" "nofile=20" "cpu=30"
check "and the second of them too" "30 30" "$(rlimit cpu)"
reads_back "the larger of two values in one file" nofile "40 40" "[limits]" "nofile=20" "nofile=40"
reads_back "a zero in the same file leaves the container's own value" nofile "$(ulimit -Sn) $(ulimit -Hn)" "[limits]" "nofile=20" "nofile=0"
refused "mem_mb too large to set safely" "$PHB_EPOLICY" "[limits]" "mem_mb=99999999999999999999"
refused "fsize_mb too large to set safely" "$PHB_EPOLICY" "[limits]" "fsize_mb=99999999999999999999"
refused "nofile above what the kernel allows is not run without it" "$PHB_ERUNTIME" "[limits]" "nofile=99999999"
refused "nofile=1, which leaves no room to start the command" 125 "[limits]" "nofile=1"
refused "nproc=0x10" "$PHB_EPOLICY" "[limits]" "nproc=0x10"
refused "a decimal point in a count" "$PHB_EPOLICY" "[limits]" "nproc=1.5"
refused "a sign in front of a count" "$PHB_EPOLICY" "[limits]" "cpu=+5"
refused "an empty value for a count" "$PHB_EPOLICY" "[limits]" "cpu="

echo
echo "== Ares 2 policies =="
# ares_accepted TITLE ENTRY...: the imported policy is accepted and the command runs and ends with status 0.
ares_accepted() {
  local title="$1"
  local config
  shift
  config="$(ares_cfg syntax "$@")"
  run_pm --config "$config" -- "$P" cwd
  if started && (( PM_STATUS == 0 )); then ok "accepted: an Ares 2 policy with ${title}"; else bad "accepted: an Ares 2 policy with ${title}" "$(pm_describe)"; fi
}
# ares_refused TITLE FROM TO: the imported policy with the line FROM replaced by TO is refused with PHB-EPOLICY before
# the command is reached.
ares_refused() {
  local title="$1"
  local config
  config="$(ares_cfg syntax "fs $PM/ro r" "net 127.0.0.1 80")"
  sed -i "s|$2|$3|" "$config"
  run_pm --config "$config" -- "$P" cwd
  if ! started && (( PM_STATUS == PHB_EPOLICY )); then ok "refused with ${PHB_EPOLICY}: an Ares 2 policy with ${title}"; else bad "refused: an Ares 2 policy with ${title}" "$(pm_describe)"; fi
}
ares_accepted "no entry at all"
ares_accepted "a read entry" "fs $PM/ro r"
ares_accepted "every right on a tree" "fs $PM/rw rwcxd"
ares_accepted "an entry that grants nothing" "fs $PM/none -"
ares_accepted "a loopback network entry with a port" "net 127.0.0.1 80"
ares_accepted "localhost on every port" "net localhost 0"
ares_accepted "a timeout" "timeout 30000"
ares_refused "version 2" "PolicyVersion: 1" "PolicyVersion: 2"
ares_refused "an unknown configuration" "$PM_ARES_CONFIGURATION" "NO_SUCH_CONFIGURATION"
ares_refused "a boolean spelt yes" "readAllFiles: true" "readAllFiles: yes"
ares_refused "a quoted port" "onThePort: 80" "onThePort: \"80\""
ares_refused "a port past 65535" "onThePort: 80" "onThePort: 70000"
ares_refused "a connection opened but no data sent" "sendData: true" "sendData: false"
ares_refused "the whole file system as a path" "\"$PM/ro\"" "\"*\""
ares_refused "a path that does not exist" "\"$PM/ro\"" "\"$PM/no-such-path\""
ares_refused "a '..' segment" "\"$PM/ro\"" "\"$PM/ro/../none\""
ares_refused "a placeholder the configuration does not name" "\"$PM/ro\"" "\"\${HOME}/x\""
ares_refused "an unknown key" "theFollowingClassesAreTestClasses: \\[\\]" "theFollowingClassesAreTestClasses: []\\n  unknownKey: 1"
ares_refused "a timeout of 0" "regardingTimeouts: \\[\\]" "regardingTimeouts:\\n      - timeout: 0"

echo
echo "== section headers and the shape of a file =="
for header in "[Read]" "[read ]" "[ read]" "[read]]" "[[read]]" "[unknown]" "[READ]" "[connect ]" "[limits ]"; do
  config="$PM/cfg/header.cfg"
  printf '%s\n%s\n' "$header" "$PM/ro" > "$config"
  run_pm --config "$config" -- "$P" cwd
  if ! started && (( PM_STATUS == PHB_EPOLICY )); then ok "refused with ${PHB_EPOLICY}: the header ${header}"; else bad "the header ${header} is refused" "$(pm_describe)"; fi
done
for header in "[read]" "[execute]" "[write]" "[create]" "[delete]" "[create-ipc]" "[create-symlink]" "[restructure]" "[connect]" "[bind]" "[accept]" "[limits]"; do
  config="$PM/cfg/header.cfg"
  printf '[read]\n%s\n%s\n' "$PM/ro" "$header" > "$config"
  run_pm --config "$config" -- "$P" cwd
  if started && (( PM_STATUS == 0 )); then ok "accepted: an empty ${header} section"; else bad "an empty ${header} section is accepted" "$(pm_describe)"; fi
done
accepted "a header followed by a comment" "[read] # a comment" "$PM/ro"
accepted "the same section twice" "[read]" "$PM/ro"
refused "a line that is only the two brackets, which is a path that is not absolute" "$PHB_EPOLICY" "[]"
refused "an unknown section after a known one" "$PHB_EPOLICY" "[read]" "[unknown]"
printf '%s\n' "$PM/ro" > "$PM/cfg/nosection.cfg"
run_pm --config "$PM/cfg/nosection.cfg" -- "$P" cwd
if ! started && (( PM_STATUS == PHB_EPOLICY )); then ok "refused with ${PHB_EPOLICY}: a path before any section header"; else bad "a path before any section" "$(pm_describe)"; fi

finish
