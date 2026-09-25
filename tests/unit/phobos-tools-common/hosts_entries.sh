#!/usr/bin/env bash
# The lines a run adds to a hosts file for an exact [connect] name, and their removal.
#
# The network layer maps an exact name to the broker's placeholder in /etc/hosts so the graded
# command can resolve it without DNS. Each line carries the run's tag, and whichever layer removes
# the run's specification directory removes exactly those lines again, in place and under a lock.
# This suite pins both directions on a scratch hosts file, so it needs no root and no sandbox: the
# lines are written and resolve-shaped while the run holds them, they are gone afterwards with every
# other byte unchanged, another run's lines and the image's own lines survive, a file with nothing to
# remove is not written, a reader never meets a fragment of a removed line, a lock the graded
# command could take on the hosts file stalls nothing, a lock that is never released ends in a
# refusal rather than a hang, and a removal that fails keeps the directory for an outer layer to
# retry. The lock lives in the suite's own scratch directory, so the suite needs no /run/lock.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../../core"
# shellcheck source=../../../core/phobos-tools-common/phobos-common.sh
source "${CORE}/phobos-tools-common/phobos-common.sh"
# shellcheck source=../../../core/phobos-tools-networksystem/phobos-haproxy.sh
source "${CORE}/phobos-tools-networksystem/phobos-haproxy.sh"
set +e
WORK="$(mktemp -d)"
cleanup() {
  [[ -n "${holder:-}" ]] && kill "$holder" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT
PHB_HOSTS_LOCK="$WORK/locks/phobos-hosts.lock"

# How many names each of the concurrent writers maps, and how many rounds the removal races a
# writer, enough for an unlocked read-modify-write to lose a line.
CONCURRENT_NAMES=25
RACE_ROUNDS=200

# Makes a specification directory marked as one Phobos owns, as phobos.sh does, and prints it.
owned_spec() {
  local directory
  directory="$(mktemp -d "$WORK/phobos-spec.XXXXXX")"
  mark_owned_spec_dir "$directory"
  mkdir -p "$directory/${PHB_SPEC_SCRATCH}"
  printf '%s\n' "$directory"
}

IMAGE_HOSTS=$'127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\n127.0.0.2 allowed.example\n'

echo "== a run maps its names with lines of its own =="
hosts="$WORK/hosts"
printf '%s' "$IMAGE_HOSTS" > "$hosts"
run_a="$(owned_spec)"
run_b="$(owned_spec)"
tag_a="$(run_hosts_tag "$run_a")"
tag_b="$(run_hosts_tag "$run_b")"
write_broker_hosts "$hosts" "$run_a" allowed.example other.example
write_broker_hosts "$hosts" "$run_a" allowed.example
check "a run's names are mapped once each, however often it writes them" "1 1" \
  "$(grep -cxF "127.0.0.2 allowed.example # ${tag_a}" "$hosts") $(grep -cxF "127.0.0.2 other.example # ${tag_a}" "$hosts")"
check "the file the run wrote to is recorded in its specification directory" "$hosts" "$(cat "$run_a/${PHB_SPEC_HOSTS_RECORD}")"
[[ "$(head -n 3 "$hosts"; printf 'x')" == "${IMAGE_HOSTS}x" ]] \
  && ok "the image's own lines stay in front of the run's, unchanged byte for byte" \
  || bad "the image's own lines stay in front of the run's, unchanged byte for byte" "$(cat "$hosts")"
write_broker_hosts "$hosts" "$run_b" allowed.example
check "a name another run already maps gets a line of this run's own" "1" \
  "$(grep -cxF "127.0.0.2 allowed.example # ${tag_b}" "$hosts")"
check "the tag follows the address and the name as a trailing comment" "127.0.0.2 other.example #" \
  "$(grep -F "other.example" "$hosts" | awk '{ print $1, $2, $3 }')"

echo "== removing one run's lines leaves everything else as it was =="
inode_before="$(stat -c %i "$hosts")"
remove_run_hosts_entries "$hosts" "$run_a"
check "removing a run's lines succeeds" "0" "$?"
check "none of the run's lines is left" "0" "$(grep -c -- "# ${tag_a}$" "$hosts")"
check "the other run's line is still there" "1" "$(grep -cxF "127.0.0.2 allowed.example # ${tag_b}" "$hosts")"
check "the file is rewritten in place, not replaced, so a bind mount keeps it" "$inode_before" "$(stat -c %i "$hosts")"
remove_run_hosts_entries "$hosts" "$run_b"
[[ "$(cat "$hosts"; printf 'x')" == "${IMAGE_HOSTS}x" ]] \
  && ok "once both runs are removed the file is byte-identical to the image's" \
  || bad "once both runs are removed the file is byte-identical to the image's" "$(cat "$hosts")"
check "an untagged mapping of the same name, as an image or an older Phobos wrote it, survives" "1" \
  "$(grep -cxF "127.0.0.2 allowed.example" "$hosts")"

echo "== a file with nothing of the run's in it is not written =="
touch -d '2000-01-01 00:00:00' "$hosts"
mtime_before="$(stat -c %Y "$hosts")"
remove_run_hosts_entries "$hosts" "$run_a"
check "removing from a file that holds none of the run's lines succeeds" "0" "$?"
check "and leaves the file unwritten" "$mtime_before" "$(stat -c %Y "$hosts")"

echo "== a file that does not end in a newline =="
bare="$WORK/hosts-bare"
printf '127.0.0.1 localhost' > "$bare"
remove_run_hosts_entries "$bare" "$run_a"
check "is left byte for byte when nothing of the run's is in it" "127.0.0.1 localhost" "$(cat "$bare"; [[ -z "$(tail -c 1 "$bare")" ]] && printf '<newline>')"
unterminated="$WORK/hosts-unterminated"
printf '127.0.0.1 localhost' > "$unterminated"
run_c="$(owned_spec)"
write_broker_hosts "$unterminated" "$run_c" allowed.example
check "the image's last line and the run's line stay two lines" "127.0.0.1 localhost|127.0.0.2 allowed.example # $(run_hosts_tag "$run_c")" \
  "$(paste -sd'|' "$unterminated")"

echo "== concurrent runs never lose one another's lines =="
shared="$WORK/hosts-shared"
printf '%s' "$IMAGE_HOSTS" > "$shared"
run_x="$(owned_spec)"
run_y="$(owned_spec)"
mapfile -t names_x < <(seq -f 'x%g.example' 1 "$CONCURRENT_NAMES")
mapfile -t names_y < <(seq -f 'y%g.example' 1 "$CONCURRENT_NAMES")
for name in "${names_x[@]}"; do write_broker_hosts "$shared" "$run_x" "$name"; done &
writer_x=$!
for name in "${names_y[@]}"; do write_broker_hosts "$shared" "$run_y" "$name"; done &
writer_y=$!
wait "$writer_x" "$writer_y"
check "two runs writing at once both keep every line" "${CONCURRENT_NAMES} ${CONCURRENT_NAMES}" \
  "$(grep -c -- "# $(run_hosts_tag "$run_x")$" "$shared") $(grep -c -- "# $(run_hosts_tag "$run_y")$" "$shared")"
lost=0
for (( round = 0; round < RACE_ROUNDS; round++ )); do
  run_r="$(owned_spec)"
  write_broker_hosts "$shared" "$run_r" "r${round}.example"
  remove_run_hosts_entries "$shared" "$run_r" &
  remover=$!
  write_broker_hosts "$shared" "$run_x" "late${round}.example"
  wait "$remover"
  grep -qxF "127.0.0.2 late${round}.example # $(run_hosts_tag "$run_x")" "$shared" || lost=$(( lost + 1 ))
  grep -q -- "# $(run_hosts_tag "$run_r")$" "$shared" && lost=$(( lost + 1 ))
done
check "a removal racing another run's write neither loses that line nor keeps its own" "0" "$lost"

echo "== a reader never sees a stale fragment of a removed line =="
fragment="$WORK/hosts-fragment"
printf '%s' "$IMAGE_HOSTS" > "$fragment"
run_s="$(owned_spec)"
run_t="$(owned_spec)"
write_broker_hosts "$fragment" "$run_s" short.example
write_broker_hosts "$fragment" "$run_t" another.example
PHB_HOSTS_TAG=" # $(run_hosts_tag "$run_s")" awk 'substr($0, length($0) - length(ENVIRON["PHB_HOSTS_TAG"]) + 1) != ENVIRON["PHB_HOSTS_TAG"]' \
  "$fragment" > "$WORK/kept"
before="$(wc -c < "$fragment")"
after="$(wc -c < "$WORK/kept")"
pad_with_comment "$WORK/kept" "$(( before - after ))"
overwrite_in_place "$WORK/kept" "$fragment" "$before"
check "the padded content fills the old length exactly" "$before" "$(wc -c < "$fragment")"
check "between the write and the truncate, every line is a kept line or a comment" "" \
  "$(grep -v -x -F -f "$WORK/kept" "$fragment" | grep -v '^#' | grep -v '^$')"
truncate -s "$after" "$fragment"
check "after the truncate, the other run's line is intact and the padding is gone" \
  "1 0" "$(grep -cxF "127.0.0.2 another.example # $(run_hosts_tag "$run_t")" "$fragment") $(grep -c '^#' "$fragment")"

echo "== the lock is one the graded command cannot hold =="
held="$WORK/hosts-held"
printf '%s' "$IMAGE_HOSTS" > "$held"
( flock -x 9; sleep 30 ) 9< "$held" &
holder=$!
sleep 0.3
run_h="$(owned_spec)"
started="$SECONDS"
write_broker_hosts "$held" "$run_h" allowed.example
check "a lock taken on the hosts file itself, as a command with read on /etc could take it, does not stall a writer" \
  "0 1" "$(( SECONDS - started > 2 )) $(grep -c -- "# $(run_hosts_tag "$run_h")$" "$held")"
remove_run_hosts_entries "$held" "$run_h"
check "nor a remover" "0" "$(grep -c -- "# $(run_hosts_tag "$run_h")$" "$held")"
kill "$holder" 2>/dev/null
wait "$holder" 2>/dev/null
holder=""
( flock -x 9; sleep 30 ) 9>> "$PHB_HOSTS_LOCK" &
holder=$!
sleep 0.3
run_w="$(owned_spec)"
PHB_HOSTS_LOCK_WAIT_SECONDS=1 write_broker_hosts "$held" "$run_w" allowed.example
check "a hosts lock nothing lets go of makes a writer give up rather than hang" "1 0" \
  "$? $(grep -c -- "# $(run_hosts_tag "$run_w")$" "$held")"
kill "$holder" 2>/dev/null
wait "$holder" 2>/dev/null
holder=""

echo "== the specification directory carries the lines' lifetime =="
lifetime="$WORK/hosts-lifetime"
printf '%s' "$IMAGE_HOSTS" > "$lifetime"
run_l="$(owned_spec)"
write_broker_hosts "$lifetime" "$run_l" allowed.example
remove_owned_spec_dir "$run_l"
check "removing the specification directory succeeds" "0" "$?"
[[ "$(cat "$lifetime"; printf 'x')" == "${IMAGE_HOSTS}x" ]] \
  && ok "and removes the run's lines with it" \
  || bad "and removes the run's lines with it" "$(cat "$lifetime")"
[[ ! -e "$run_l" ]] && ok "and the directory, record included" || bad "and the directory, record included" "$(ls -A "$run_l")"
run_n="$(owned_spec)"
remove_owned_spec_dir "$run_n"
check "a run that mapped no name is removed without a record" "0" "$?"
run_k="$(owned_spec)"
: > "$run_k/${PHB_SPEC_HOSTS_KEPT}.AbC123"
remove_owned_spec_dir "$run_k"
[[ ! -e "$run_k" ]] && ok "a copy of the hosts file a killed clean-up left behind does not keep the directory for ever" \
  || bad "a copy of the hosts file a killed clean-up left behind does not keep the directory for ever" "$(ls -A "$run_k")"
strip_status="$(bash -c 'set -e; source "$1"; source "$2"; strip_run_hosts_entries "$3" "$4" "$5"; echo reached' _ \
  "${CORE}/phobos-tools-common/phobos-common.sh" "${CORE}/phobos-tools-networksystem/phobos-haproxy.sh" \
  "$hosts" "$run_a" "$WORK/strip-kept" 2>&1)"
check "finding nothing to remove does not end a caller running under set -e" "reached" "$strip_status"
run_f="$(owned_spec)"
printf '%s\n' "$WORK/no-such-hosts" > "$run_f/${PHB_SPEC_HOSTS_RECORD}"
remove_owned_spec_dir "$run_f"
removal_status=$?
[[ "$removal_status" != 0 && -f "$run_f/${PHB_SPEC_HOSTS_RECORD}" && -f "$run_f/${PHB_SPEC_MARKER}" ]] \
  && ok "a removal of the lines that fails keeps the directory and its record, so an outer layer tries again" \
  || bad "a removal of the lines that fails keeps the directory and its record" "status=${removal_status} left=$(ls -A "$run_f" 2>/dev/null | tr '\n' ' ')"

finish
