#!/usr/bin/env bash
# Proves Landlock's TCP bind-port rule against the real kernel: with --bind-tcp naming one port, a
# raw bind to that port passes, a raw bind to any other port is refused with EACCES, and a raw bind
# to port 0 (a kernel-chosen ephemeral port) is refused too, so a submission cannot open a listener
# on a port the policy did not name, the public port an [accept] rule fronts included, not even by a
# raw system call. With the bind layer off (no --bind-tcp) the same bind passes, so the refusal is
# the kernel's doing. This is the port containment the inbound filter relies on, judged end to end
# rather than as a recorded ruleset.
#
# It needs the run-phase image and an ordinary container: no --privileged, no --cap-add,
# no --security-opt.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
LANDLOCK="${CORE}/phobos-landlock-filesystem-and-networksystem"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ALLOWED_PORT=18080
DENIED_PORT=18099
EACCES_ERRNO=13

cat > "$WORK/bind_probe.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
/* Binds a TCP socket to a port with a raw bind system call, so no libc wrapper can
 * stand between the call and the kernel, and reports whether the kernel allowed it. Arguments: the
 * port, where 0 asks the kernel for an ephemeral one, then optionally "udp" for a datagram socket or
 * "listen" to call listen() on a socket that was never bound, which the kernel gives a port of its
 * own choosing. */
int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }
    int type = SOCK_STREAM;
    if (argc >= 3 && strcmp(argv[2], "udp") == 0) {
        type = SOCK_DGRAM;
    }
    int fd = (int)syscall(SYS_socket, AF_INET, type, 0);
    if (argc >= 3 && strcmp(argv[2], "listen") == 0) {
        long listened = syscall(SYS_listen, fd, 4);
        if (listened == 0) {
            printf("LISTEN-OK\n");
        } else {
            printf("LISTEN-DENIED errno=%d\n", errno);
        }
        return 0;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)atoi(argv[1]));
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    long result = syscall(SYS_bind, fd, (struct sockaddr *)&address, sizeof(address));
    if (result == 0) {
        printf("BIND-OK %s\n", argv[1]);
    } else {
        printf("BIND-DENIED %s errno=%d\n", argv[1], errno);
    }
    return 0;
}
C

compiler=gcc-14
command -v "$compiler" >/dev/null 2>&1 || compiler=gcc
"$compiler" -O2 -o "$WORK/bind_probe" "$WORK/bind_probe.c" 2>"$WORK/cc.log" \
  || { bad "compile the bind probe" "$(cat "$WORK/cc.log")"; finish; }

# Runs the raw-bind probe under phobos-landlock-filesystem-and-networksystem. Arguments: port to bind, then any landlock args.
run() {
  local port=$1
  shift
  "$LANDLOCK" --rights=rx /opt --rights=rx /usr --rights=rx /lib --rights=rx "$WORK" "$@" \
    -- "$WORK/bind_probe" "$port" 2>&1
}

echo "== with the Landlock bind layer on (allow only ${ALLOWED_PORT}) =="
out="$(run "$ALLOWED_PORT" --bind-tcp "$ALLOWED_PORT")"
[[ "$out" == *"BIND-OK ${ALLOWED_PORT}"* ]] && ok "the allowed port binds" || bad "the allowed port binds" "$out"
out="$(run "$DENIED_PORT" --bind-tcp "$ALLOWED_PORT")"
[[ "$out" == *"BIND-DENIED ${DENIED_PORT} errno=${EACCES_ERRNO}"* ]] && ok "another port is refused by the kernel, raw syscall and all" \
  || bad "another port is refused by the kernel, raw syscall and all" "$out"
out="$(run 0 --bind-tcp "$ALLOWED_PORT")"
[[ "$out" == *"BIND-DENIED 0 errno=${EACCES_ERRNO}"* ]] && ok "a kernel-chosen ephemeral port is refused too" \
  || bad "a kernel-chosen ephemeral port is refused too" "$out"

echo
echo "== control: with the bind layer off, the same bind passes =="
out="$(run "$DENIED_PORT")"
[[ "$out" == *"BIND-OK ${DENIED_PORT}"* ]] && ok "no --bind-tcp means the bind is not stopped by Landlock" \
  || bad "no --bind-tcp means the bind is not stopped by Landlock" "$out"

echo
echo "== through the network layer: bind is closed unless a [bind] row opens it =="
LAYER="${CORE}/phobos-networksystem.sh"
# Runs the probe under the network layer over a hand-written specification: the bind.rules body
# first, then the probe's own arguments. The net.rules is empty, so every connect is refused too,
# which these probes never make. The warnings the layer prints about a kernel too old to close
# UDP bind are part of the output, so a check can read them.
layer_run() {
  local spec
  spec="$(mktemp -d "$WORK/spec.XXXXXX")"
  : > "$spec/net.rules"
  printf '%s' "$1" > "$spec/bind.rules"
  shift
  "$LAYER" "$spec" -- "$WORK/bind_probe" "$@" 2>&1
}

out="$(layer_run "" 8080)"
[[ "$out" == *"BIND-DENIED 8080 errno=${EACCES_ERRNO}"* ]] && ok "with no [bind] row, an explicit port is refused" \
  || bad "with no [bind] row, an explicit port is refused" "$out"
out="$(layer_run "" 0)"
[[ "$out" == *"BIND-DENIED 0 errno=${EACCES_ERRNO}"* ]] && ok "with no [bind] row, a kernel-chosen port is refused too" \
  || bad "with no [bind] row, a kernel-chosen port is refused too" "$out"

out="$(layer_run $'* 0\n' 0)"
[[ "$out" == *"BIND-OK 0"* ]] && ok "a [bind] port 0 row lets a server take a port the kernel chooses" \
  || bad "a [bind] port 0 row lets a server take a port the kernel chooses" "$out"
out="$(layer_run $'* 0\n' 8080)"
[[ "$out" == *"BIND-DENIED 8080 errno=${EACCES_ERRNO}"* ]] && ok "a [bind] port 0 row does not let it name a port of its own" \
  || bad "a [bind] port 0 row does not let it name a port of its own" "$out"

out="$(layer_run $'* 8080\n' 8080)"
[[ "$out" == *"BIND-OK 8080"* ]] && ok "an explicit [bind] port binds" || bad "an explicit [bind] port binds" "$out"
out="$(layer_run $'* 8080\n' 0)"
[[ "$out" == *"BIND-DENIED 0 errno=${EACCES_ERRNO}"* ]] && ok "an explicit [bind] port does not open the kernel's own choice" \
  || bad "an explicit [bind] port does not open the kernel's own choice" "$out"

out="$(layer_run "" 0 listen)"
[[ "$out" == *"LISTEN-DENIED errno=${EACCES_ERRNO}"* ]] && ok "with no [bind] row, listen() on a socket that was never bound is refused" \
  || bad "with no [bind] row, listen() on a socket that was never bound is refused" "$out"
out="$(layer_run $'* 8080\n' 0 listen)"
[[ "$out" == *"LISTEN-DENIED errno=${EACCES_ERRNO}"* ]] && ok "an explicit [bind] port does not let an unbound socket listen either" \
  || bad "an explicit [bind] port does not let an unbound socket listen either" "$out"
out="$(layer_run $'* 0\n' 0 listen)"
[[ "$out" == *"LISTEN-OK"* ]] && ok "a [bind] port 0 row lets an unbound socket listen, it grants the same kernel-chosen port" \
  || bad "a [bind] port 0 row lets an unbound socket listen, it grants the same kernel-chosen port" "$out"
out="$("$WORK/bind_probe" 0 listen 2>&1)"
[[ "$out" == *"LISTEN-OK"* ]] && ok "control: outside the layer the same unbound listen works" \
  || bad "control: outside the layer the same unbound listen works" "$out"

LANDLOCK_ABI="$("$LANDLOCK" --verbose --rights=rx /usr -- /bin/true 2>&1 | sed -n 's/.*Landlock version \([0-9]*\).*/\1/p')"
echo
echo "== UDP bind, on this kernel's Landlock version ${LANDLOCK_ABI:-unknown} =="
if [[ "${LANDLOCK_ABI:-0}" -ge 10 ]]; then
  out="$(layer_run "" 8080 udp)"
  [[ "$out" == *"BIND-DENIED 8080 errno=${EACCES_ERRNO}"* ]] && ok "with no [bind] row, a UDP port is refused" \
    || bad "with no [bind] row, a UDP port is refused" "$out"
  out="$(layer_run $'* 0 udp\n' 0 udp)"
  [[ "$out" == *"BIND-OK 0"* ]] && ok "a [bind] udp port 0 row lets a socket take a port the kernel chooses" \
    || bad "a [bind] udp port 0 row lets a socket take a port the kernel chooses" "$out"
  out="$(layer_run $'* 0 udp\n' 8080 udp)"
  [[ "$out" == *"BIND-DENIED 8080 errno=${EACCES_ERRNO}"* ]] && ok "a [bind] udp port 0 row does not let it name a port of its own" \
    || bad "a [bind] udp port 0 row does not let it name a port of its own" "$out"
else
  skip "UDP bind is closed unless a [bind] row opens it" "the kernel offers Landlock version ${LANDLOCK_ABI:-unknown}, UDP rights need 10, so this was not run"
  out="$(layer_run "" 8080 udp)"
  [[ "$out" == *"BIND-OK 8080"* && "$out" == *"cannot close UDP bind"* ]] && ok "on a kernel below version 10, a UDP bind stays open and the layer says so" \
    || bad "on a kernel below version 10, a UDP bind stays open and the layer says so" "$out"
fi

finish
