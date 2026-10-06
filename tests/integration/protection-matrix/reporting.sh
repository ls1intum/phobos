#!/usr/bin/env bash
# Denial reporting through phobos.sh and the standalone filesystem layer. Every case compares the probe's
# own result (return value and errno) with and without the reporter, so the reporter is shown to change
# nothing, and then requires either success and no line, or the same refusal and exactly one line.
# The calls the timeout layer's group lock refuses outright are held to the same contract: refused with
# EACCES and reported while the reporter serves, refused with ENOSYS once it is dead or absent, and
# never run. Run inside the run-phase image, in an ordinary container. See lib.sh for what makes a
# denial count.
#
# Until the connect guard reports (PR 3 of the denial-reporting plan), the filesystem layer starts its
# own reporter only with the network layer off, so every switch set below carries -nnr; the standalone
# filesystem layer is the ninth entry.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${PM_HERE}/lib.sh"
pm_setup || finish
trap pm_restore EXIT
P="$PM/bin/pprobe"
PREFIX='Phobos Security Error: the program tried to illegally '
SUFFIX=' but was blocked by Phobos.'
ENFORCER="${PHOBOS_HOME}/phobos-landlock-filesystem-and-networksystem"
REPORTER="${PHOBOS_HOME}/phobos-seccomp-filesystem"
cd "$PM/work" || exit 1

# Two helpers of this suite's own. tick reads a granted and a refused file and calls setsid once a second,
# printing what each answered, so a supervisor can be killed between two rounds. holdlistener installs a
# seccomp listener that traps one call nobody makes and keeps it open across exec, so a supervisor started
# beneath it cannot install its own (EBUSY) and the group lock's refusals meet no listener.
cat > "$PM/out/tick.c" <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
static const char *name_of(int error) {
    return error == 0 ? "OK" : error == EACCES ? "EACCES" : error == ENOSYS ? "ENOSYS" : "OTHER";
}
static int try_open(const char *path) {
    int descriptor = open(path, O_RDONLY);
    if (descriptor < 0) {
        return errno;
    }
    close(descriptor);
    return 0;
}
int main(int argument_count, char *arguments[]) {
    if (argument_count < 4) {
        return 2;
    }
    int rounds = atoi(arguments[3]);
    for (int round = 0; round < rounds; round++) {
        int granted = try_open(arguments[1]);
        int refused = try_open(arguments[2]);
        long session = syscall(SYS_setsid);
        int session_error = session < 0 ? errno : 0;
        long group = syscall(SYS_setpgid, 0, 0);
        int group_error = group < 0 ? errno : 0;
        printf("TICK %d granted=%s refused=%s setsid=%s setpgid=%s\n", round, name_of(granted),
               name_of(refused), name_of(session_error), name_of(group_error));
        fflush(stdout);
        struct timespec second = {.tv_sec = 1, .tv_nsec = 0};
        nanosleep(&second, NULL);
    }
    return 0;
}
C
cat > "$PM/out/holdlistener.c" <<'C'
#define _GNU_SOURCE
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argument_count, char *arguments[]) {
    if (argument_count < 2) {
        return 2;
    }
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_acct, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = 4, .filter = instructions};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return 3;
    }
    int listener = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    if (listener < 0 || dup2(listener, 200) < 0) {
        return 4;
    }
    execvp(arguments[1], &arguments[1]);
    return 5;
}
C
cat > "$PM/out/renames.c" <<'C'
#include <stdio.h>
#include <stdlib.h>
int main(int argument_count, char *arguments[]) {
    if (argument_count < 4) {
        return 2;
    }
    int rounds = atoi(arguments[3]);
    for (int round = 0; round < rounds; round += 2) {
        if (rename(arguments[1], arguments[2]) != 0 || rename(arguments[2], arguments[1]) != 0) {
            perror("rename");
            return 1;
        }
    }
    return 0;
}
C
gcc-14 -std=gnu23 -O2 -o "$PM/bin/tick" "$PM/out/tick.c" 2>"$PM/out/cc-tick.log" || bad "the tick helper builds" "$(cat "$PM/out/cc-tick.log")"
gcc-14 -std=gnu23 -O2 -o "$PM/bin/renames" "$PM/out/renames.c" 2>"$PM/out/cc-renames.log" || bad "the rename helper builds" "$(cat "$PM/out/cc-renames.log")"
gcc-14 -std=gnu23 -O2 -o "$PM/bin/holdlistener" "$PM/out/holdlistener.c" 2>"$PM/out/cc-hold.log" || bad "the listener holder builds" "$(cat "$PM/out/cc-hold.log")"

rm -rf "$PM"/rw/* "$PM"/rw2/* 2>/dev/null
printf 'RW-OK\n' > "$PM/rw/data.txt"
printf 'RW2-OK\n' > "$PM/rw2/a"

# Every right but REFER on rw and rw2, read and execute on ro, nothing on none.
c_rw="$(cfg rw <<EOF2
[read]
$PM/rw
$PM/rw2
$PM/ro
[write]
$PM/rw
$PM/rw2
[create]
$PM/rw
$PM/rw2
[delete]
$PM/rw
$PM/rw2
[create-ipc]
$PM/rw
[create-symlink]
$PM/rw
[execute]
$PM/ro
EOF2
)"
# The same with REFER, so a file may be moved and linked between rw and rw2.
c_refer="$(cfg refer <<EOF2
[read]
$PM/rw
$PM/rw2
$PM/ro
[write]
$PM/rw
$PM/rw2
[restructure]
$PM/rw
$PM/rw2
EOF2
)"
# No timeout, so the timeout layer applies no group lock and nothing refuses setsid.
c_untimed="$(cfg untimed <<EOF2
[read]
$PM/rw
[limits]
timeout=0
EOF2
)"

# Runs the standalone filesystem layer with the arguments given, under the watchdog, into PM_OUT, PM_ERR and
# PM_STATUS, as run_pm does for phobos.sh.
run_layer() {
  PM_OUT="$PM/out/last.out"
  PM_ERR="$PM/out/last.err"
  timeout --kill-after=5 "$WATCHDOG_SECONDS" phobos-filesystem.sh --tail-flags-file "$PM/tail.flags" "$@" \
    > "$PM_OUT" 2> "$PM_ERR" < /dev/null
  PM_STATUS=$?
}

# Counts the report lines of the last run that name anything under the matrix's own tree, so a line about
# the dynamic loader or a start-up read cannot make a case pass or fail.
own_report_lines() {
  grep "^${PREFIX}" "$PM_ERR" | grep -cF "$PM/"
}

# Counts the lines of the last run's standard error that are exactly the report given.
exact_lines() {
  grep -cxF -- "${PREFIX}$1${SUFFIX}" "$PM_ERR"
}

# reported_case TITLE SWITCHES CONFIG OPNAME ERRNOS LINE -- PROBE ARGS...
# The baseline is the standalone filesystem layer with --no-own-reporter: Landlock alone. The reported run is
# phobos.sh with SWITCHES, or the standalone layer with its own reporter for "standalone". Their results for
# OPNAME must be identical. With ERRNOS empty the operation must succeed and no line may name the matrix's
# tree; otherwise it must fail with one of ERRNOS and LINE must appear exactly once, as the only line naming
# the matrix's tree. PREP, when set, runs before each of the two runs.
reported_case() {
  local title="$1"
  local switches="$2"
  local config="$3"
  local opname="$4"
  local errnos="$5"
  local line="$6"
  local baseline
  local reported
  shift 7
  pm_prep
  run_layer --no-own-reporter --config "$config" -- "$@"
  baseline="$(op_result "$opname")"
  pm_prep
  if [[ "$switches" == standalone ]]; then
    run_layer --config "$config" -- "$@"
  else
    # SWITCHES is a space-separated list of options, none of which holds a space.
    # shellcheck disable=SC2086
    run_pm $switches --config "$config" -- "$@"
  fi
  reported="$(op_result "$opname")"
  if [[ -z "$baseline" || "$baseline" != "$reported" ]]; then
    bad "$title" "the reporter changed the result: without [${baseline}], with [${reported}] $(pm_describe)"
    return 0
  fi
  if [[ -z "$errnos" ]]; then
    if op_ok "$opname" && [[ "$(own_report_lines)" == 0 ]]; then ok "$title"; else bad "$title" "$(pm_describe)"; fi
    return 0
  fi
  # ERRNOS is a space-separated list of errno names.
  # shellcheck disable=SC2086
  if op_failed_with "$opname" $errnos && [[ "$(exact_lines "$line")" == 1 ]] && [[ "$(own_report_lines)" == 1 ]]; then
    ok "$title"
  else
    bad "$title" "expected one line [${line}]: $(pm_describe)"
  fi
}

echo
echo "== every action is refused or granted exactly as without the reporter, with one line per refusal =="
for switches in "-nnr" "-nnr -ntr" "-nnr -nrr" "-nnr -ntr -nrr" standalone; do
  PREP=""
  reported_case "granted read [${switches}]" "$switches" "$c_rw" open "" "" -- "$P" read "$PM/rw/data.txt"
  reported_case "refused read [${switches}]" "$switches" "$c_rw" open "EACCES" \
    "read the File '$PM/none/secret.txt'" -- "$P" read "$PM/none/secret.txt"
  reported_case "granted write [${switches}]" "$switches" "$c_rw" open "" "" -- "$P" write "$PM/rw/data.txt" RW-OK
  reported_case "refused write [${switches}]" "$switches" "$c_rw" open "EACCES" \
    "write the File '$PM/ro/data.txt'" -- "$P" write "$PM/ro/data.txt" x
  PREP="rm -f '$PM/rw/new.txt' '$PM/ro/new.txt'"
  reported_case "granted create [${switches}]" "$switches" "$c_rw" open "" "" -- "$P" write "$PM/rw/new.txt" x
  reported_case "refused create [${switches}]" "$switches" "$c_rw" open "EACCES" \
    "create the File '$PM/ro/new.txt'" -- "$P" write "$PM/ro/new.txt" x
  PREP="rm -rf '$PM/rw/d' '$PM/ro/d'"
  reported_case "granted mkdir [${switches}]" "$switches" "$c_rw" mkdir "" "" -- "$P" mkdir "$PM/rw/d"
  reported_case "refused mkdir [${switches}]" "$switches" "$c_rw" mkdir "EACCES" \
    "create the Directory '$PM/ro/d'" -- "$P" mkdir "$PM/ro/d"
  PREP="printf x > '$PM/rw/gone'"
  reported_case "granted unlink [${switches}]" "$switches" "$c_rw" unlink "" "" -- "$P" unlink "$PM/rw/gone"
  PREP=""
  reported_case "refused unlink [${switches}]" "$switches" "$c_rw" unlink "EACCES" \
    "delete the File '$PM/ro/data.txt'" -- "$P" unlink "$PM/ro/data.txt"
  PREP="mkdir -p '$PM/rw/empty' '$PM/ro/empty'"
  reported_case "granted rmdir [${switches}]" "$switches" "$c_rw" rmdir "" "" -- "$P" rmdir "$PM/rw/empty"
  reported_case "refused rmdir [${switches}]" "$switches" "$c_rw" rmdir "EACCES" \
    "delete the Directory '$PM/ro/empty'" -- "$P" rmdir "$PM/ro/empty"
  PREP="rm -f '$PM/rw2/moved'; printf x > '$PM/rw/move-me'"
  reported_case "granted move with REFER [${switches}]" "$switches" "$c_refer" rename "" "" \
    -- "$P" rename "$PM/rw/move-me" "$PM/rw2/moved"
  reported_case "refused move without REFER [${switches}]" "$switches" "$c_rw" rename "EXDEV" \
    "move the File '$PM/rw/move-me' to '$PM/rw2/moved'" -- "$P" rename "$PM/rw/move-me" "$PM/rw2/moved"
  PREP="rm -f '$PM/rw2/linked'"
  reported_case "granted link with REFER [${switches}]" "$switches" "$c_refer" link "" "" \
    -- "$P" link "$PM/rw/data.txt" "$PM/rw2/linked"
  reported_case "refused link without REFER [${switches}]" "$switches" "$c_rw" link "EXDEV" \
    "link the File '$PM/rw/data.txt' to '$PM/rw2/linked'" -- "$P" link "$PM/rw/data.txt" "$PM/rw2/linked"
  PREP="printf b > '$PM/rw/b'"
  reported_case "granted exchange [${switches}]" "$switches" "$c_rw" renameat2_exchange "" "" \
    -- "$P" renameat2_exchange "$PM/rw/data.txt" "$PM/rw/b"
  reported_case "refused exchange [${switches}]" "$switches" "$c_rw" renameat2_exchange "EACCES EXDEV" \
    "create the File '$PM/ro/data.txt'" -- "$P" renameat2_exchange "$PM/rw/b" "$PM/ro/data.txt"
  PREP=""
  reported_case "granted execute [${switches}]" "$switches" "$c_rw" exec "" "" -- "$P" exec "$PM/ro/pprobe-static" whoami
  reported_case "refused execute [${switches}]" "$switches" "$c_rw" exec "EACCES" \
    "execute the File '$PM/none/pprobe-static'" -- "$P" exec "$PM/none/pprobe-static" whoami
  PREP="rm -f '$PM/rw/fifo' '$PM/rw2/fifo' '$PM/rw/sock' '$PM/rw2/sock' '$PM/rw/sl' '$PM/rw2/sl' '$PM/rw/tty'"
  reported_case "granted named pipe [${switches}]" "$switches" "$c_rw" mkfifo "" "" -- "$P" mkfifo "$PM/rw/fifo"
  reported_case "refused named pipe [${switches}]" "$switches" "$c_rw" mkfifo "EACCES" \
    "create the Named Pipe '$PM/rw2/fifo'" -- "$P" mkfifo "$PM/rw2/fifo"
  reported_case "granted socket file [${switches}]" "$switches" "$c_rw" bind_unix "" "" -- "$P" mksock "$PM/rw/sock"
  reported_case "refused socket file [${switches}]" "$switches" "$c_rw" bind_unix "EACCES" \
    "create the Socket File '$PM/rw2/sock'" -- "$P" mksock "$PM/rw2/sock"
  reported_case "granted symbolic link [${switches}]" "$switches" "$c_rw" symlink "" "" -- "$P" symlink /target "$PM/rw/sl"
  reported_case "refused symbolic link [${switches}]" "$switches" "$c_rw" symlink "EACCES" \
    "create the Symbolic Link '$PM/rw2/sl'" -- "$P" symlink /target "$PM/rw2/sl"
  reported_case "refused device [${switches}]" "$switches" "$c_rw" mknod_char "EACCES" \
    "create the Device '$PM/rw/tty'" -- "$P" mknod_char "$PM/rw/tty"
  PREP="printf 'RW-OK\n' > '$PM/rw/data.txt'"
  reported_case "granted truncate [${switches}]" "$switches" "$c_rw" truncate "" "" -- "$P" truncate "$PM/rw/data.txt" 2
  reported_case "refused truncate [${switches}]" "$switches" "$c_rw" truncate "EACCES" \
    "write the File '$PM/ro/data.txt'" -- "$P" truncate "$PM/ro/data.txt" 2
  PREP="ln -sfn '$PM/none/secret.txt' '$PM/rw/to-none'"
  reported_case "a refused read through a link names both paths [${switches}]" "$switches" "$c_rw" open "EACCES" \
    "read the File '$PM/none/secret.txt' (named as '$PM/rw/to-none')" -- "$P" read "$PM/rw/to-none"
done
PREP=""
printf 'RW-OK\n' > "$PM/rw/data.txt"

echo
echo "== with the filesystem layer off nothing is refused, so nothing is reported =="
run_pm -nnr --no-filesystem-restriction --config "$c_rw" -- "$P" read "$PM/none/secret.txt"
if op_ok open && [[ "$(own_report_lines)" == 0 ]]; then ok "-nfr reports nothing"; else bad "-nfr reports nothing" "$(pm_describe)"; fi
echo
echo "== with the network layer on, the connect guard is the supervisor, which reports from PR 3 =="
run_pm --config "$c_rw" -- "$P" read "$PM/none/secret.txt"
if op_failed_with open EACCES && [[ "$(own_report_lines)" == 0 ]] && ! grep -q 'reporting is off' "$PM_ERR"; then
  ok "a run with the network layer on starts no second reporter beside the guard, and its refusal still holds"
else
  bad "a run with the network layer on starts no second reporter beside the guard" "$(pm_describe)"
fi

echo
echo "== a refusal repeated in a loop is one line, and the cap holds =="
run_pm -nnr --config "$c_rw" -- /bin/sh -c "i=0; while [ \$i -lt 2000 ]; do true 2>/dev/null < '$PM/none/secret.txt'; i=\$((i+1)); done; echo LOOPED"
if grep -q LOOPED "$PM_OUT" && [[ "$(exact_lines "read the File '$PM/none/secret.txt'")" == 1 ]]; then
  ok "2000 refused reads of one file print one line"
else
  bad "2000 refused reads of one file print one line" "$(pm_describe)"
fi
mkdir -p "$PM/none/many"
for number in $(seq 1 150); do printf x > "$PM/none/many/f${number}"; done
run_pm -nnr --config "$c_rw" -- /bin/sh -c "i=1; while [ \$i -le 150 ]; do true 2>/dev/null < '$PM/none/many/f'\$i; i=\$((i+1)); done; echo LOOPED"
if grep -q LOOPED "$PM_OUT" && [[ "$(grep -c "^${PREFIX}read the File '$PM/none/many/" "$PM_ERR")" == 100 ]] \
  && [[ "$(grep -cxF 'Phobos: further blocked actions are counted but not shown.' "$PM_ERR")" == 1 ]]; then
  ok "150 distinct refused files print 100 lines and the overflow notice once"
else
  bad "150 distinct refused files print 100 lines and the overflow notice once" "$(grep -c "^${PREFIX}" "$PM_ERR") lines: $(pm_describe)"
fi

echo
echo "== a name with a control byte is quoted =="
odd="$PM/ro/x"$'\n'"name"
run_pm -nnr --config "$c_rw" -- "$P" write "$odd" x
if op_failed_with open EACCES && [[ "$(grep -cxF "${PREFIX}create the File \$'$PM/ro/x\\nname'${SUFFIX}" "$PM_ERR")" == 1 ]]; then
  ok "a refused create of a name with a newline prints it quoted, on one line"
else
  bad "a refused create of a name with a newline prints it quoted, on one line" "$(pm_describe)"
fi

echo
echo "== only the tasks of the Landlock domain are judged =="
run_pm -nnr --config "$c_rw" -- "$P" read "$PM/rw/data.txt"
if op_ok open && ! grep -q "^${PREFIX}.*${PHOBOS_HOME}" "$PM_ERR"; then
  ok "the layers' own reads of ${PHOBOS_HOME} before the restriction print nothing"
else
  bad "the layers' own reads of ${PHOBOS_HOME} before the restriction print nothing" "$(pm_describe)"
fi
run_direct "$REPORTER" --landlock-bin "$ENFORCER" -- /bin/sh -c \
  "cat '$PM/none/secret.txt' > /dev/null; exec '$ENFORCER' --mark-reported-domain --rights=rx /usr --rights=rx /lib --rights=rx /bin --rights=rx '$PM/bin' -- '$P' read '$PM/none/secret.txt'"
if op_failed_with open EACCES && [[ "$(exact_lines "read the File '$PM/none/secret.txt'")" == 1 ]]; then
  ok "a helper's read outside the domain prints nothing, the same read inside it one line"
else
  bad "a helper's read outside the domain prints nothing, the same read inside it one line" "$(pm_describe)"
fi

echo
echo "== the group lock's refusals: EACCES and one line while the reporter serves, never run =="
for switches in "-nnr" "-nnr -nfr"; do
  run_pm $switches --config "$c_rw" -- "$P" setsid
  if op_failed_with setsid EACCES && [[ "$(exact_lines "leave the Session")" == 1 ]]; then
    ok "setsid is refused with EACCES and reported [${switches}]"
  else
    bad "setsid is refused with EACCES and reported [${switches}]" "$(pm_describe)"
  fi
  run_pm $switches --config "$c_rw" -- "$P" setpgid
  if op_failed_with setpgid EACCES && [[ "$(exact_lines "leave the Process Group")" == 1 ]]; then
    ok "setpgid is refused with EACCES and reported [${switches}]"
  else
    bad "setpgid is refused with EACCES and reported [${switches}]" "$(pm_describe)"
  fi
done
run_pm -nnr -ntr --config "$c_rw" -- "$P" setsid
if op_ok setsid && [[ "$(grep -c "^${PREFIX}" "$PM_ERR")" == 0 ]]; then
  ok "without the timeout layer no filter refuses setsid, so it succeeds and nothing is reported"
else
  bad "without the timeout layer no filter refuses setsid, so it succeeds and nothing is reported" "$(pm_describe)"
fi
run_pm -nnr --config "$c_untimed" -- "$P" setsid
if op_ok setsid && [[ "$(grep -c "^${PREFIX}" "$PM_ERR")" == 0 ]]; then
  ok "nor with a timeout layer that applies no lock, because no timeout is set"
else
  bad "nor with a timeout layer that applies no lock, because no timeout is set" "$(pm_describe)"
fi
run_layer --config "$c_rw" -- "$P" setsid
if op_ok setsid && [[ "$(grep -c "^${PREFIX}" "$PM_ERR")" == 0 ]]; then
  ok "a standalone filesystem layer never traps setsid"
else
  bad "a standalone filesystem layer never traps setsid" "$(pm_describe)"
fi
run_layer --group-lock-above --config "$c_rw" -- "$P" setsid
if op_ok setsid && [[ "$(grep -c "^${PREFIX}" "$PM_ERR")" == 0 ]] && grep -q "its signature was not found" "$PM_ERR"; then
  ok "told the group lock is above when it is not, the reporter finds no signature, says so and refuses nothing"
else
  bad "told the group lock is above when it is not, the reporter finds no signature, says so and refuses nothing" "$(pm_describe)"
fi

echo
echo "== a supervisor that is gone: every trapped call fails with ENOSYS, and none succeeds =="
bg_pm "$PM/out/tick.out" "$PM/out/tick.err" -nnr --config "$c_rw" -- "$PM/bin/tick" "$PM/rw/data.txt" "$PM/none/secret.txt" 6
wait_for_line "$PM/out/tick.out" "TICK 1 " 60 || bad "the tick helper starts" "$(cat "$PM/out/tick.err")"
supervisor="$(pgrep -o -f "^${REPORTER} ")"
if [[ "$supervisor" =~ ^[1-9][0-9]*$ ]]; then
  kill -KILL "$supervisor"
  wait_for_line "$PM/out/tick.out" "TICK 5 " 100
  wait "$BG_PID" 2>/dev/null
  before="$(grep -m1 '^TICK 0 ' "$PM/out/tick.out")"
  after="$(grep '^TICK 5 ' "$PM/out/tick.out")"
  check "before the kill: granted, and refused three times" "TICK 0 granted=OK refused=EACCES setsid=EACCES setpgid=EACCES" "$before"
  check "after it: every trapped call fails with ENOSYS" "TICK 5 granted=ENOSYS refused=ENOSYS setsid=ENOSYS setpgid=ENOSYS" "$after"
  check "and in no round did the refused read, setsid or setpgid succeed" "0" \
    "$(grep -cE '^TICK [0-9]+ .*(refused=OK|setsid=OK|setpgid=OK)' "$PM/out/tick.out")"
else
  bad "the supervisor can be found to kill" "no process runs ${REPORTER}"
  reap "$BG_PID"
fi

echo
echo "== a supervisor that never installed its filter: the group lock refuses with ENOSYS, nothing is reported =="
PM_OUT="$PM/out/last.out"
PM_ERR="$PM/out/last.err"
timeout --kill-after=5 "$WATCHDOG_SECONDS" "$PM/bin/holdlistener" phobos.sh --tail-flags-file "$PM/tail.flags" -nnr \
  --config "$c_rw" -- "$P" setsid > "$PM_OUT" 2> "$PM_ERR" < /dev/null
PM_STATUS=$?
if op_failed_with setsid ENOSYS && grep -q "another supervisor already holds the run's listener" "$PM_ERR" \
  && [[ "$(grep -c "^${PREFIX}" "$PM_ERR")" == 0 ]]; then
  ok "beneath another listener the reporter says so once, and setsid is refused with ENOSYS and not reported"
else
  bad "beneath another listener the reporter says so once, and setsid is refused with ENOSYS and not reported" "$(pm_describe)"
fi
run_pm -nnr --config "$c_rw" -- "$PM/bin/holdlistener" "$P" read "$PM/none/secret.txt"
if (( PM_STATUS == 4 )) && [[ -z "$(op_result open)" ]]; then
  ok "the command cannot install a listener of its own beneath the reporter, so it cannot take the supervision over"
else
  bad "the command cannot install a listener of its own beneath the reporter" "$(pm_describe)"
fi

echo
echo "== the cost of a rename loop, recorded, not gated =="
rm -f "$PM/rw/r2"
printf x > "$PM/rw/r1"
start="$(now_ms)"
run_layer --no-own-reporter --config "$c_rw" -- "$PM/bin/renames" "$PM/rw/r1" "$PM/rw/r2" 10000
without=$(( $(now_ms) - start ))
without_status="$PM_STATUS"
start="$(now_ms)"
run_layer --config "$c_rw" -- "$PM/bin/renames" "$PM/rw/r1" "$PM/rw/r2" 10000
with=$(( $(now_ms) - start ))
if (( without_status == 0 && PM_STATUS == 0 )); then
  ok "10000 granted renames run with and without the reporter"
  echo "  10000 renames: ${without} ms under Landlock alone, ${with} ms with the reporter (whole run, not gated)"
else
  bad "10000 granted renames run with and without the reporter" "status ${without_status} and ${PM_STATUS}: $(pm_describe)"
fi

finish
