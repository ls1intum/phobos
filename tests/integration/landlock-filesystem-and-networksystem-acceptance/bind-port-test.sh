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
 * stand between the call and the kernel, and reports whether the kernel allowed it. Argument: the
 * port, where 0 asks the kernel for an ephemeral one. */
int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }
    int fd = (int)syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
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

finish
