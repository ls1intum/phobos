#!/usr/bin/env bash
# Proves the ioctl right on a device, and the [ioctl] section that grants it, in both directions.
#
# Landlock (ABI 5 and later) refuses an ioctl on a character or block device that was opened without the
# ioctl right on its path. A pseudo-terminal is the case that matters: openpty() opens /dev/ptmx, issues
# TIOCSPTLCK and TIOCGPTN on it, opens the slave, and a terminal program then issues more. This suite
# builds a small static probe that does exactly that, step by step, and runs it
#   - outside any sandbox, as the control: every step succeeds, so a later refusal is Landlock's and not a missing
#     devpts, a DAC failure or an ENOTTY;
#   - with read and write on /dev/pts and no ioctl right: the master opens and the first ioctl is refused (EACCES);
#   - with the ioctl right alone: the open itself is refused, because the right grants nothing else;
#   - with read, write and ioctl on /dev/pts: every step works and bytes pass between master and slave;
#   - with the right on /dev/pts only: an ioctl on another device (/dev/null) is still refused with EACCES,
#     where the control gets ENOTTY, so the refusal is not a stand-in for an unsupported operation;
#   - through the policy: [read], [write] and [ioctl] on /dev/pts give the whole exchange, the same policy
#     without [ioctl] stops at the first ioctl, and an [ioctl] entry written as the symbolic link /dev/ptmx is
#     refused by the enforcer, which never anchors a rule that can change something on a link.
#
# It needs the run-phase image and an ordinary container: no --privileged, no --cap-add, no --security-opt, and
# its own devpts instance, which Docker gives every container. Below Landlock ABI 5 a device ioctl is not
# restricted at all, so the suite skips there.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
LANDLOCK="${CORE}/phobos-landlock-filesystem-and-networksystem"
FIRST_LANDLOCK_VERSION_WITH_IOCTL_DEVICE=5
PROBE_DIR=/var/tmp/ioctl-probe
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}" "${PROBE_DIR}"' EXIT

version="$("$LANDLOCK" --verbose --rights=rx /usr -- /bin/true 2>&1 \
  | sed -n 's/.*Landlock version \([0-9][0-9]*\).*/\1/p' | head -1)"
if [[ -z "$version" ]] || (( version < FIRST_LANDLOCK_VERSION_WITH_IOCTL_DEVICE )); then
  skip "the ioctl right on a device" "the kernel offers Landlock version ${version:-<none>}; the right needs ${FIRST_LANDLOCK_VERSION_WITH_IOCTL_DEVICE}"
  finish
fi
if [[ ! -e /dev/ptmx || ! -d /dev/pts ]]; then
  skip "the ioctl right on a device" "this container has no /dev/ptmx and /dev/pts"
  finish
fi

mkdir -p "${PROBE_DIR}" /var/tmp/testing-dir
cat > "${WORK}/probe.c" <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

static int step(const char *name, int ok) {
    printf("%s=%d\n", name, ok ? 0 : errno);
    fflush(stdout);
    return ok;
}

int main(int argument_count, char *arguments[]) {
    if (argument_count < 2) {
        return 2;
    }
    if (strcmp(arguments[1], "other") == 0) {
        int descriptor = open("/dev/null", O_RDWR);
        if (!step("open_null", descriptor >= 0)) {
            return 1;
        }
        struct termios attributes;
        step("ioctl_null", ioctl(descriptor, TCGETS, &attributes) == 0);
        return 0;
    }
    int master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (!step("open_ptmx", master >= 0)) {
        return 1;
    }
    int unlock = 0;
    if (!step("unlock", ioctl(master, TIOCSPTLCK, &unlock) == 0)) {
        return 1;
    }
    unsigned int number = 0;
    if (!step("number", ioctl(master, TIOCGPTN, &number) == 0)) {
        return 1;
    }
    char name[64];
    snprintf(name, sizeof(name), "/dev/pts/%u", number);
    int slave = open(name, O_RDWR | O_NOCTTY);
    if (!step("open_slave", slave >= 0)) {
        return 1;
    }
    struct termios attributes;
    if (!step("slave_get", tcgetattr(slave, &attributes) == 0)) {
        return 1;
    }
    struct winsize size = {.ws_row = 24, .ws_col = 80};
    if (!step("slave_size", ioctl(slave, TIOCSWINSZ, &size) == 0)) {
        return 1;
    }
    struct winsize back;
    step("master_size", ioctl(master, TIOCGWINSZ, &back) == 0 && back.ws_row == 24 && back.ws_col == 80);
    cfmakeraw(&attributes);
    step("slave_set", tcsetattr(slave, TCSANOW, &attributes) == 0);
    char buffer[8] = {0};
    step("exchange", write(master, "ping", 4) == 4 && read(slave, buffer, 4) == 4 && memcmp(buffer, "ping", 4) == 0);
    return 0;
}
C
compiler=""
for candidate in gcc-14 gcc cc; do
  if command -v "$candidate" >/dev/null 2>&1; then compiler="$candidate"; break; fi
done
if [[ -z "$compiler" ]] || ! "$compiler" -O2 -static -o "${PROBE_DIR}/probe" "${WORK}/probe.c" 2>"${WORK}/cc.log"; then
  skip "the ioctl right on a device" "the probe did not build: $(cat "${WORK}/cc.log" 2>/dev/null)"
  finish
fi

ALL_STEPS="open_ptmx=0 unlock=0 number=0 open_slave=0 slave_get=0 slave_size=0 master_size=0 slave_set=0 exchange=0"

# The probe's steps as one line, whatever happens.
steps() { tr '\n' ' ' | sed 's/ *$//'; }

control="$("${PROBE_DIR}/probe" pty 2>&1 | steps)"
check "the control, outside any sandbox, completes every step" "$ALL_STEPS" "$control"
control_other="$("${PROBE_DIR}/probe" other 2>&1 | steps)"
check "and the control's ioctl on /dev/null is refused by the device with ENOTTY (25), not by anything else" "open_null=0 ioctl_null=25" "$control_other"

under() {
  "$LANDLOCK" --rights=rx "${PROBE_DIR}" --rights="$1" /dev/pts --rights=rw /dev/null -- "${PROBE_DIR}/probe" "$2" 2>&1 | grep -E '^[a-z_]+=[0-9]+$' | steps
}

check "with read and write on /dev/pts, the master opens and the first ioctl is refused (EACCES, 13)" \
  "open_ptmx=0 unlock=13" "$(under rw pty)"
check "with the ioctl right alone, the open is refused: the right grants nothing else" \
  "open_ptmx=13" "$(under i pty)"
check "with read, write and ioctl on /dev/pts, every step works and bytes pass from master to slave" \
  "$ALL_STEPS" "$(under rwi pty)"
check "the right on /dev/pts does not reach /dev/null: its ioctl is refused with EACCES (13), where the control got ENOTTY" \
  "open_null=0 ioctl_null=13" "$(under rwi other)"

echo
echo "== through the policy =="
printf '[read]\n%s\n/dev/pts\n[execute]\n%s\n[write]\n/dev/pts\n' "${PROBE_DIR}" "${PROBE_DIR}" > "${WORK}/without.cfg"
{ cat "${WORK}/without.cfg"; printf '[ioctl]\n/dev/pts\n'; } > "${WORK}/with.cfg"
policy() {
  "${CORE}/phobos.sh" --config "$1" -- "${PROBE_DIR}/probe" pty 2>/dev/null | grep -E '^[a-z_]+=[0-9]+$' | steps
}
check "a policy with [read], [write] and [ioctl] on /dev/pts lets the probe do every step" "$ALL_STEPS" "$(policy "${WORK}/with.cfg")"
check "the same policy without [ioctl] stops at the first ioctl (EACCES, 13)" "open_ptmx=0 unlock=13" "$(policy "${WORK}/without.cfg")"

if [[ -L /dev/ptmx ]]; then
  { cat "${WORK}/without.cfg"; printf '[ioctl]\n/dev/ptmx\n'; } > "${WORK}/link.cfg"
  link_out="$("${CORE}/phobos.sh" --config "${WORK}/link.cfg" -- "${PROBE_DIR}/probe" pty 2>&1)"
  link_rc=$?
  if (( link_rc != 0 )) && ! grep -q '^unlock=0' <<<"$link_out"; then
    ok "an [ioctl] entry written as the symbolic link /dev/ptmx is refused, and the probe does not run"
  else
    bad "an [ioctl] entry written as the symbolic link /dev/ptmx is refused, and the probe does not run" "$link_out"
  fi
else
  skip "an [ioctl] entry on a symbolic link" "/dev/ptmx is not a symbolic link here"
fi

finish
