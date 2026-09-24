#!/usr/bin/env bash
# Each layer runs on its own from one or more --config files: it builds a specification of its
# own through the one parser, phobos-policy.sh, enforces only its own concern, and removes the
# specification directory afterwards rather than leaking it.
#
# Both directions per layer: the network layer denies a forbidden connect and leaves the
# filesystem alone; the filesystem layer denies a path the policy does not name and leaves the
# network alone; the timeout layer stops a command that overruns and lets a quick one finish; the
# resources layer applies a configured limit and applies none without one. And a policy that would
# place the specification directory beneath a write path is refused in standalone mode too, since
# every layer builds through the same parser.
#
# It needs a C compiler that knows C23, a kernel with Landlock and seccomp filtering, and python3
# for the socket probe. Where any is missing the checks skip, saying so.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harness.sh
source "${HERE}/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../core"
# shellcheck source=../core/phobos-constants.sh
source "${CORE}/phobos-constants.sh"
WORK="$(mktemp -d)"
export TMPDIR="$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

compiler=gcc-14
command -v "$compiler" >/dev/null 2>&1 || compiler=gcc
if ! command -v "$compiler" >/dev/null 2>&1; then
  skip "standalone layers" "no C compiler to build the enforcers"
  finish
fi
if ! command -v python3 >/dev/null 2>&1; then
  skip "standalone layers" "python3 is not installed, so the socket probe cannot run"
  finish
fi

# The core, with the three enforcers built beside phobos-policy.sh and a minimal base policy that
# names only paths that exist here, so phobos-landlock-filesystem-and-networksystem does not refuse a base path that is absent.
CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
rm -f "$CORE_X"/Base*.cfg
for c in landlock-filesystem-and-networksystem seccomp-networksystem seccomp-timeoutsystem; do
  case "$c" in
    landlock-filesystem-and-networksystem) src=("$CORE_X"/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem*.c) ;;
    seccomp-networksystem) src=("$CORE_X"/phobos-seccomp-networksystem/phobos-seccomp-networksystem*.c) ;;
    seccomp-timeoutsystem) src=("$CORE_X"/phobos-seccomp-timeoutsystem/phobos-seccomp-timeoutsystem.c) ;;
  esac
  if ! "$compiler" -std=gnu23 -O2 -Wall -Wextra -Werror -o "$WORK/phobos-$c" "${src[@]}" 2>"$WORK/cc.log"; then
    skip "standalone layers" "phobos-$c did not build: $(cat "$WORK/cc.log")"
    finish
  fi
  # The compiled binary takes the place of its source folder, so $CORE_X holds the enforcers flat
  # beside the scripts, as the run-phase image ships them, and the runs below find them by name.
  rm -rf "$CORE_X/phobos-$c"
  mv "$WORK/phobos-$c" "$CORE_X/phobos-$c"
done
printf '[read]\n/usr\n/bin\n/lib\n/etc\n[execute]\n/usr\n/bin\n/lib\n/etc\n[connect]\nallow 127.0.0.1:*\n' \
  > "$CORE_X/BaseTest.cfg"

SPECS="$WORK/specs"
mkdir -p "$SPECS"
echo SECRET > "$WORK/secret.txt"
# An exercise config that adds nothing beyond the base, so the work directory holding the secret
# file is never granted: the filesystem layer must therefore deny reading it, while the network
# layer, which does not touch the filesystem, leaves it readable. The command itself is /bin/sh or
# python3, which the base grants under /usr and /bin; the connect probe runs only under the
# network layer, where the filesystem is unrestricted.
printf '[read]\n/usr\n' > "$WORK/probe.cfg"

# A probe that connects to an address and prints the errno, and one that opens a socket and says
# so, to tell an enforced layer from an unenforced one.
cat > "$WORK/connect-probe.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
int main(int argument_count, char *arguments[]) {
    if (argument_count < 3) {
        return 2;
    }
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0) {
        printf("socket-errno=%d\n", errno);
        return 0;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)atoi(arguments[2]));
    inet_pton(AF_INET, arguments[1], &address.sin_addr);
    int result = connect(descriptor, (struct sockaddr *)&address, sizeof(address));
    printf("connect-errno=%d\n", result == 0 ? 0 : errno);
    return 0;
}
C
if ! "$compiler" -std=gnu23 -O2 -o "$WORK/connect-probe" "$WORK/connect-probe.c" 2>"$WORK/cc.log"; then
  skip "standalone layers" "the connect probe did not build: $(cat "$WORK/cc.log")"
  finish
fi

# Skip whole where Landlock cannot be applied here (an old kernel or a restrictive container),
# the same way the other enforcement suites do.
if ! "$CORE_X/phobos-landlock-filesystem-and-networksystem" --rights=rx /usr -- /bin/true 2>"$WORK/ll.log"; then
  skip "standalone layers" "Landlock could not be applied here: $(cat "$WORK/ll.log")"
  finish
fi

# Runs a layer in config mode under a bounded outer timeout, with every run's specification made
# under this suite's own parent rather than the default /var/tmp, so the leak check at the end can
# see a directory a broken clean-up would have left behind.
run_layer() {
  local layer=$1
  shift
  timeout 30s bash "$CORE_X/$layer" --spec-parent "$SPECS" "$@" 2>&1
}

echo "== the network layer alone enforces the network and leaves the filesystem =="
net_out="$(run_layer phobos-network.sh --connect-guard-bin "$CORE_X/phobos-seccomp-networksystem" \
  --landlock-bin "$CORE_X/phobos-landlock-filesystem-and-networksystem" --config "$WORK/probe.cfg" -- "$WORK/connect-probe" 8.8.8.8 53)"
if [[ "$net_out" == *"connect-errno=13"* ]]; then
  ok "the network layer alone denies a forbidden connect"
else
  bad "the network layer alone denies a forbidden connect" "connect-errno=13" "$(printf '%s' "$net_out" | tail -1)"
fi
net_fs="$(run_layer phobos-network.sh --connect-guard-bin "$CORE_X/phobos-seccomp-networksystem" \
  --landlock-bin "$CORE_X/phobos-landlock-filesystem-and-networksystem" --config "$WORK/probe.cfg" -- /bin/sh -c "cat $WORK/secret.txt")"
if [[ "$net_fs" == *"SECRET"* ]]; then
  ok "the network layer alone leaves the filesystem unrestricted"
else
  bad "the network layer alone leaves the filesystem unrestricted" "the secret file readable" "$(printf '%s' "$net_fs" | tail -1)"
fi

echo
echo "== the filesystem layer alone enforces the filesystem and leaves the network =="
fs_deny="$(run_layer phobos-filesystem.sh --landlock-bin "$CORE_X/phobos-landlock-filesystem-and-networksystem" \
  --config "$WORK/probe.cfg" -- /bin/sh -c "cat $WORK/secret.txt 2>&1")"
if [[ "$fs_deny" == *"Permission denied"* ]]; then
  ok "the filesystem layer alone denies a path the policy does not name"
else
  bad "the filesystem layer alone denies a path the policy does not name" "Permission denied" "$(printf '%s' "$fs_deny" | tail -1)"
fi
# A connect, not merely a socket: the connect guard supervises connect(), not socket(), so a
# socket would open whether or not a network layer were present. Under the filesystem layer alone
# there is no guard, so a connect to a host the base policy does not name returns an ordinary
# network error (or succeeds), never the guard's EACCES; a present network layer would return
# EACCES here, so "not EACCES" distinguishes the two. python3 is under /usr, which the base grants.
fs_net="$(run_layer phobos-filesystem.sh --landlock-bin "$CORE_X/phobos-landlock-filesystem-and-networksystem" \
  --config "$WORK/probe.cfg" -- python3 -c '
import socket
s = socket.socket()
s.settimeout(3)
try:
    s.connect(("8.8.8.8", 53))
    print("connect-errno=0")
except OSError as error:
    print(f"connect-errno={error.errno}")')"
if [[ "$fs_net" == *"connect-errno="* && "$fs_net" != *"connect-errno=13"* ]]; then
  ok "the filesystem layer alone leaves the network unrestricted (a connect is not the guard's EACCES)"
else
  bad "the filesystem layer alone leaves the network unrestricted (a connect is not the guard's EACCES)" "a connect-errno other than 13" "$(printf '%s' "$fs_net" | tail -1)"
fi

echo
echo "== the timeout layer alone stops an overrun and lets a quick command finish =="
printf '[read]\n/usr\n[limits]\ntimeout=1\n' > "$WORK/t1.cfg"
to_out="$(run_layer phobos-timeout.sh --pgroup-lock-bin "$CORE_X/phobos-seccomp-timeoutsystem" \
  --config "$WORK/t1.cfg" -- sleep 10)"
if [[ "$to_out" == *"Timed out after 1s"* ]]; then
  ok "the timeout layer alone stops a command that overruns"
else
  bad "the timeout layer alone stops a command that overruns" "a PHB-ETIMEOUT message" "$(printf '%s' "$to_out" | tail -1)"
fi
quick="$(run_layer phobos-timeout.sh --pgroup-lock-bin "$CORE_X/phobos-seccomp-timeoutsystem" \
  --config "$WORK/t1.cfg" -- /bin/echo quick-ok)"
if [[ "$quick" == *"quick-ok"* ]]; then
  ok "the timeout layer alone lets a quick command finish"
else
  bad "the timeout layer alone lets a quick command finish" "quick-ok" "$(printf '%s' "$quick" | tail -1)"
fi

echo
echo "== the resources layer alone applies a configured limit and none without one =="
printf '[read]\n/usr\n[limits]\nmem_mb=256\n' > "$WORK/mem.cfg"
mem="$(run_layer phobos-resources.sh --config "$WORK/mem.cfg" -- /bin/bash -c 'echo mem=$(ulimit -v)')"
if [[ "$mem" == *"mem=262144"* ]]; then
  ok "the resources layer alone applies the configured memory limit"
else
  bad "the resources layer alone applies the configured memory limit" "mem=262144" "$(printf '%s' "$mem" | tail -1)"
fi
nomem="$(run_layer phobos-resources.sh --config "$CORE_X/BaseTest.cfg" -- /bin/bash -c 'echo mem=$(ulimit -v)')"
if [[ "$nomem" == *"mem=unlimited"* ]]; then
  ok "the resources layer alone applies no limit when none is named"
else
  bad "the resources layer alone applies no limit when none is named" "mem=unlimited" "$(printf '%s' "$nomem" | tail -1)"
fi

echo
echo "== a standalone layer still refuses a specification directory beneath a write path =="
printf '[read]\n/usr\n[write]\n%s\n[create]\n%s\n' "$SPECS" "$SPECS" > "$WORK/writespec.cfg"
under_out="$(run_layer phobos-resources.sh --config "$WORK/writespec.cfg" -- /bin/true)"
under_rc=$?
if [[ "$under_out" == *"lies beneath the write path"* ]]; then
  ok "a standalone layer refuses a specification beneath a write path (via the one parser)"
else
  bad "a standalone layer refuses a specification beneath a write path (via the one parser)" "a PHB-EPOLICY refusal" "exit ${under_rc}: $(printf '%s' "$under_out" | tail -1)"
fi

echo
echo "== no specification directory is left behind by any standalone run =="
if ls -d "$SPECS"/phobos-spec.* >/dev/null 2>&1; then
  bad "standalone runs leave no specification behind" "no phobos-spec.* under the parent" "$(ls -d "$SPECS"/phobos-spec.* 2>/dev/null | tr '\n' ' ')"
else
  ok "standalone runs leave no specification behind"
fi

finish
