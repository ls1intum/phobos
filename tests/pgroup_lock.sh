#!/usr/bin/env bash
# phobos-pgroup-lock refuses setsid and setpgid, so a command the timeout layer bounds cannot
# start a new session or process group and step out of the group GNU timeout kills.
#
# Two directions. Directly: setsid and setpgid are refused with EACCES under the lock and are
# not refused without it, and an ordinary command still runs. End to end: with the network
# restriction off, so the connect guard's own refusal of these calls is absent, a timed run whose
# command tries to detach a child with setsid still has that child killed with the group, because
# the timeout layer applies the lock itself. And a timed run refuses to start when the lock binary
# is missing, rather than run a command that could outlive its timeout.
#
# It needs a C compiler that knows C23 (for the lock and a small probe), a kernel with seccomp
# filtering, GNU timeout and ps. Where any is missing the checks skip, saying so.
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
  skip "the group lock" "no C compiler to build it"
  finish
fi
if ! command -v timeout >/dev/null 2>&1; then
  skip "the group lock" "GNU timeout is not installed"
  finish
fi
if ! command -v ps >/dev/null 2>&1; then
  skip "the group lock" "ps is not installed, so a survivor cannot be looked for"
  finish
fi
if ! command -v setsid >/dev/null 2>&1; then
  skip "the group lock" "the setsid command is not installed, so the escape cannot be attempted"
  finish
fi

LOCK="$WORK/phobos-pgroup-lock"
if ! "$compiler" -std=gnu23 -O2 -Wall -Wextra -Werror -o "$LOCK" "${CORE}/phobos-pgroup-lock.c" 2>"$WORK/cc.log"; then
  skip "the group lock" "it did not build, so the kernel or compiler is too old: $(cat "$WORK/cc.log")"
  finish
fi

# A probe that makes one of the two calls and prints the errno it got, or 0 for success, so the
# suite can tell a seccomp refusal (EACCES) from an ordinary one and from success.
cat > "$WORK/probe.c" <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argument_count, char *arguments[]) {
    if (argument_count < 2) {
        return 2;
    }
    long result = 0;
    if (strcmp(arguments[1], "setsid") == 0) {
        result = setsid();
    } else {
        result = setpgid(0, 0);
    }
    printf("%d\n", result < 0 ? errno : 0);
    return 0;
}
C
if ! "$compiler" -std=gnu23 -O2 -o "$WORK/probe" "$WORK/probe.c" 2>"$WORK/cc.log"; then
  skip "the group lock" "the probe did not build: $(cat "$WORK/cc.log")"
  finish
fi

# A seccomp filter is refused on a kernel without it, so the lock cannot be applied; skip rather
# than fail, the same way the connect guard's suite does where seccomp is absent.
if ! "$LOCK" -- /bin/true 2>"$WORK/lock.log"; then
  skip "the group lock" "the lock could not be applied here: $(cat "$WORK/lock.log")"
  finish
fi

echo "== the lock refuses setsid and setpgid, and lets an ordinary call through =="
check "setsid is refused with EACCES under the lock" "13" "$("$LOCK" -- "$WORK/probe" setsid)"
check "setpgid is refused with EACCES under the lock" "13" "$("$LOCK" -- "$WORK/probe" setpgid)"
if [[ "$("$WORK/probe" setsid)" != "13" ]]; then
  ok "setsid is not refused with EACCES without the lock"
else
  bad "setsid is not refused with EACCES without the lock" "an errno other than 13" "13"
fi
if "$LOCK" -- /bin/echo ran >/dev/null 2>&1; then
  ok "an ordinary command still runs under the lock"
else
  bad "an ordinary command still runs under the lock" "exit 0" "a non-zero exit"
fi

echo
echo "== a missing lock binary is refused fail-closed when a timeout is set =="
# The whole chain, with a stand-in for phobos-landlock so no Landlock kernel is needed and the
# network restriction off so the connect guard is absent, over a base policy that sets a timeout.
CORE_X="$WORK/core-x"
cp -R "$CORE" "$CORE_X"
chmod +x "$CORE_X"/*.sh
cp "$LOCK" "$CORE_X/phobos-pgroup-lock"
printf '[read]\n/usr\n[limits]\ntimeout=3\n' > "$CORE_X/BaseTest.cfg"
printf '%s\n' '#!/usr/bin/env bash' \
  'while [[ $# -gt 0 && "$1" != "--" ]]; do shift; done; shift; exec "$@"' > "$WORK/passthrough-landlock"
chmod +x "$WORK/passthrough-landlock"
SPECS="$WORK/specs"
mkdir -p "$SPECS"

miss_out="$(timeout 30s bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" \
  --landlock-bin "$WORK/passthrough-landlock" --pgroup-lock-bin "$WORK/does-not-exist" \
  --no-networksystem-restriction -- /bin/true 2>&1)"
miss_rc=$?
if [[ "$miss_rc" -eq "$PHB_ERUNTIME" && "$miss_out" == *"group lock"* ]]; then
  ok "a timed run with a missing lock binary is refused (PHB-ERUNTIME)"
else
  bad "a timed run with a missing lock binary is refused (PHB-ERUNTIME)" "exit ${PHB_ERUNTIME} naming the group lock" "exit ${miss_rc}: ${miss_out}"
fi

echo
echo "== with the network off, the lock still stops a setsid child escaping the timeout =="
# The command backgrounds a child that tries to detach with setsid and outlive the 3s timeout.
# The lock refuses setsid, so the child stays in the group the timeout kills. The network is off,
# so this is the lock's doing, not the connect guard's. A unique marker names the child so a
# survivor of this run is told from any other sleep on the machine.
marker="phobos_pgroup_probe_$$"
timeout 30s bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" \
  --landlock-bin "$WORK/passthrough-landlock" --no-networksystem-restriction \
  -- /bin/sh -c "setsid sleep 40 >/dev/null 2>&1 </dev/null & echo ${marker}; sleep 30" \
  > "$WORK/chain.out" 2>&1
sleep 1
if ps -eo args | grep -q "[s]leep 40"; then
  # Only ours counts; there is no other sleep 40 in this container, but be explicit.
  survivor="$(ps -eo pid,args | grep "[s]leep 40" | head -1)"
  bad "a setsid child cannot escape the timeout with the network off" "no surviving sleep" "$survivor"
else
  ok "a setsid child cannot escape the timeout with the network off"
fi
if grep -qF "$marker" "$WORK/chain.out"; then
  ok "the command ran under the lock before the timeout stopped it"
else
  bad "the command ran under the lock before the timeout stopped it" "the marker on stdout" "$(tail -2 "$WORK/chain.out")"
fi

echo
echo "== with the network on, the connect guard still traps a forbidden connect under the lock =="
# The lock's ALLOW-everything filter is stacked under the connect guard's own filter, which traps
# connect to a user-notification. The kernel takes the stricter action where they overlap, so the
# guard still decides every connect although the lock is in force. This exercises both layers on,
# with a timeout set, over a loopback-only policy so no broker is needed and the network layer's
# own Landlock is not invoked. It needs the connect guard, so it is built here.
if "$compiler" -std=gnu23 -O2 -Wall -Wextra -Werror -o "$WORK/guard" "${CORE}"/phobos-connect-guard*.c 2>"$WORK/guard-cc.log"; then
  cp "$WORK/guard" "$CORE_X/phobos-connect-guard"
  cat > "$WORK/connect-probe.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
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
  if "$compiler" -std=gnu23 -O2 -o "$WORK/connect-probe" "$WORK/connect-probe.c" 2>"$WORK/probe-cc.log"; then
    printf '[read]\n/usr\n[connect]\nallow 127.0.0.1:*\n[limits]\ntimeout=3\n' > "$CORE_X/BaseTest.cfg"
    guard_out="$(timeout 30s bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" \
      --landlock-bin "$WORK/passthrough-landlock" -- "$WORK/connect-probe" 8.8.8.8 53 2>&1)"
    if [[ "$guard_out" == *"connect-errno=13"* ]]; then
      ok "the connect guard denies a forbidden connect with the lock and a timeout in force"
    else
      bad "the connect guard denies a forbidden connect with the lock and a timeout in force" "connect-errno=13 (EACCES)" "$(printf '%s' "$guard_out" | tail -1)"
    fi
    run_out="$(timeout 30s bash "$CORE_X/phobos.sh" --spec-parent "$SPECS" \
      --landlock-bin "$WORK/passthrough-landlock" -- /bin/echo guard-ran 2>&1)"
    if [[ "$run_out" == *"guard-ran"* ]]; then
      ok "an ordinary command still runs with both the guard and the lock in force"
    else
      bad "an ordinary command still runs with both the guard and the lock in force" "guard-ran on stdout" "$(printf '%s' "$run_out" | tail -1)"
    fi
  else
    skip "the guard under the lock" "the connect probe did not build: $(cat "$WORK/probe-cc.log")"
  fi
else
  skip "the guard under the lock" "the connect guard did not build: $(cat "$WORK/guard-cc.log")"
fi

finish
