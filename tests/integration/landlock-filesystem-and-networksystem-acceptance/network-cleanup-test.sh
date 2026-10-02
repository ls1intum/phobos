#!/usr/bin/env bash
# The network layer leaves nothing behind. Executes inside an ordinary container:
# no --privileged, no --cap-add, no --security-opt.
#
# The network layer starts HAProxy for an [accept] rule and for a [connect] rule that names a host,
# and maps an exact [connect] name to a placeholder in /etc/hosts. Each case proves both directions
# on the image an exercise gets: while the command runs, the inbound filter answers on its public
# port and the name resolves to the placeholder; once the run has ended, no HAProxy is left, the
# public port is free, /etc/hosts is byte-identical to what it was before, and no specification
# directory remains. That holds through phobos.sh, for the layer run on its own from a config and
# over a specification directory, after a timeout that has to escalate to SIGKILL, and for two runs
# mapping the same name at once. A run that maps no name does not touch /etc/hosts at all. It runs
# as the container's root, as the image does, because the layer writes /etc/hosts.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
# The image carries the constants beside the scripts under test.
# shellcheck source=/dev/null
source "${CORE}/phobos-tools-common/phobos-constants.sh"
TD=/var/tmp/testing-dir
WORK="$(mktemp -d)"
# The public port the inbound filter fronts and the backend port behind it; the name the
# [connect] rule maps; an address for the broker's resolver, which no case needs to reach, because
# a name only has to resolve to the placeholder inside the run; the timeout the escalation case
# sets, which the command outlives by ignoring TERM; and how long the concurrent runs overlap.
PUBLIC_PORT=28180
BACKEND_PORT=18180
NAME=allowed.example
RESOLVER=127.0.0.1:53
ESCALATION_TIMEOUT_SECONDS=2
OVERLAP_SECONDS=3

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

hdr() { printf '\n\033[1m%s\033[0m\n' "$*"; }

mkdir -p "$TD"
# A base of this suite's own, as run-tests.sh uses one: the commands below need only the system
# directories, and a base without the shipped loopback wildcard lets an exercise name a port.
cat > "$CORE/BaseLanguage-java.cfg" <<'CFG'
[read]
/bin
/etc
/lib
/lib64
/usr
/var/tmp/testing-dir
/dev/null
[execute]
/bin
/lib
/lib64
/usr
[write]
/dev/null
CFG
printf '[bind]\nallow %s\n[accept]\nexpose %s to %s from 127.0.0.1\n[connect]\nallow 127.0.0.1:%s\n' \
  "$BACKEND_PORT" "$PUBLIC_PORT" "$BACKEND_PORT" "$PUBLIC_PORT" > "$WORK/accept.cfg"
printf '[connect]\nallow %s:443\n' "$NAME" > "$WORK/name.cfg"
printf '[connect]\nallow %s:443\n[limits]\ntimeout = %s\n' "$NAME" "$ESCALATION_TIMEOUT_SECONDS" > "$WORK/escalate.cfg"
printf '[limits]\ntimeout = 30\n' > "$WORK/plain.cfg"
HOSTS_BEFORE="$(cat /etc/hosts; printf 'x')"

# Reports whether this run left anything behind: an HAProxy, the public port still answering,
# /etc/hosts changed, or a specification directory. Takes the name of the case.
nothing_left_behind() {
  local case="$1"
  local left=""
  pgrep -x haproxy > /dev/null && left+="haproxy still running; "
  (exec 3<>"/dev/tcp/127.0.0.1/${PUBLIC_PORT}") 2>/dev/null && left+="public port still answers; "
  [[ "$(cat /etc/hosts; printf 'x')" == "$HOSTS_BEFORE" ]] || left+="/etc/hosts changed: $(grep -F "$NAME" /etc/hosts | tr '\n' ' '); "
  compgen -G "/var/tmp/phobos-spec.*" > /dev/null && left+="specification directory left: $(echo /var/tmp/phobos-spec.*); "
  if [[ -z "$left" ]]; then
    ok "${case}: nothing is left behind once the run has ended"
  else
    bad "${case}: nothing is left behind once the run has ended" "$left"
  fi
}

hdr "1. The inbound filter answers during the run and is gone after it"
out="$(phobos.sh --config "$WORK/accept.cfg" -- bash -c "exec 3<>/dev/tcp/127.0.0.1/${PUBLIC_PORT} && echo FILTER-UP" 2>&1)"
[[ "$out" == *FILTER-UP* ]] && ok "phobos.sh: the command reaches the filter's public port while it runs" \
  || bad "phobos.sh: the command reaches the filter's public port while it runs" "$(tail -3 <<<"$out")"
nothing_left_behind "phobos.sh with [accept]"

out="$(phobos-networksystem.sh --config "$WORK/accept.cfg" -- bash -c "exec 3<>/dev/tcp/127.0.0.1/${PUBLIC_PORT} && echo FILTER-UP" 2>&1)"
[[ "$out" == *FILTER-UP* ]] && ok "the network layer alone: the command reaches the filter's public port while it runs" \
  || bad "the network layer alone: the command reaches the filter's public port while it runs" "$(tail -3 <<<"$out")"
nothing_left_behind "the network layer alone with [accept]"

hdr "2. An exact name resolves during the run and its mapping is gone after it"
out="$(phobos.sh --resolver "$RESOLVER" --config "$WORK/name.cfg" -- getent hosts "$NAME" 2>&1)"
[[ "$out" == *"127.0.0.2"*"$NAME"* ]] && ok "phobos.sh: the name resolves to the placeholder while the run holds it" \
  || bad "phobos.sh: the name resolves to the placeholder while the run holds it" "$(tail -3 <<<"$out")"
nothing_left_behind "phobos.sh with an exact name"

out="$(phobos-networksystem.sh --resolver "$RESOLVER" --config "$WORK/name.cfg" -- getent hosts "$NAME" 2>&1)"
[[ "$out" == *"127.0.0.2"*"$NAME"* ]] && ok "the network layer alone from a config: the name resolves while the run holds it" \
  || bad "the network layer alone from a config: the name resolves while the run holds it" "$(tail -3 <<<"$out")"
nothing_left_behind "the network layer alone from a config"

spec="$(mktemp -d /var/tmp/phobos-spec.XXXXXX)"
: > "$spec/.phobos-owned-spec"
phobos-policysystem.sh --spec-dir "$spec" --config "$WORK/name.cfg" > /dev/null 2>&1
out="$(phobos-networksystem.sh --resolver "$RESOLVER" "$spec" -- getent hosts "$NAME" 2>&1)"
[[ "$out" == *"127.0.0.2"*"$NAME"* ]] && ok "the network layer over a specification directory: the name resolves while the run holds it" \
  || bad "the network layer over a specification directory: the name resolves while the run holds it" "$(tail -3 <<<"$out")"
nothing_left_behind "the network layer over a specification directory"

hdr "3. A timeout that escalates to SIGKILL still leaves nothing behind"
status=0
phobos.sh --resolver "$RESOLVER" --config "$WORK/escalate.cfg" -- \
  bash -c "trap '' TERM; getent hosts ${NAME}; sleep 60" > "$WORK/escalate.out" 2>/dev/null || status=$?
check "the run ends at the timeout" "$PHB_ETIMEOUT" "$status"
grep -q "127.0.0.2" "$WORK/escalate.out" 2>/dev/null && ok "the name resolved while the run held it" \
  || bad "the name resolved while the run held it" "$(cat "$WORK/escalate.out" 2>/dev/null)"
nothing_left_behind "a timeout escalated to SIGKILL"

hdr "4. Two runs mapping the same name keep it for one another"
phobos.sh --resolver "$RESOLVER" --config "$WORK/name.cfg" -- \
  bash -c "sleep ${OVERLAP_SECONDS}; getent hosts ${NAME}" > "$WORK/long.out" 2>&1 &
long_run=$!
sleep 1
phobos.sh --resolver "$RESOLVER" --config "$WORK/name.cfg" -- getent hosts "$NAME" > "$WORK/short.out" 2>&1
wait "$long_run"
grep -q "127.0.0.2" "$WORK/short.out" && ok "the shorter run resolves the name" \
  || bad "the shorter run resolves the name" "$(tail -3 "$WORK/short.out")"
grep -q "127.0.0.2" "$WORK/long.out" && ok "the longer run still resolves it after the shorter one has cleaned up" \
  || bad "the longer run still resolves it after the shorter one has cleaned up" "$(tail -3 "$WORK/long.out")"
nothing_left_behind "two overlapping runs"

hdr "5. A run that maps no name does not touch /etc/hosts"
touch -d '2000-01-01 00:00:00' /etc/hosts
mtime_before="$(stat -c %Y /etc/hosts)"
phobos.sh --config "$WORK/plain.cfg" -- true > /dev/null 2>&1
check "the hosts file is not written by a run without an exact name" "$mtime_before" "$(stat -c %Y /etc/hosts)"

finish
