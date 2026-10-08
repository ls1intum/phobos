#!/usr/bin/env bash
# The filesystem layer through phobos.sh: every right one by one on an allowed tree against a sibling and a
# parent, the rights against each other, the edge cases of paths, and the documented gaps.
# Run inside the run-phase image, in an ordinary container. See lib.sh for what makes a denial count.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${PM_HERE}/lib.sh"
pm_setup || finish
trap pm_restore EXIT
PM_ABI="$(pm_abi)"
P="$PM/bin/pprobe"
SELF_STATUS_EPOLICY=11
echo "  landlock ABI ${PM_ABI}, uid ${PM_USER_ID}"
cd "$PM/work" || exit 1

rm -rf "$PM"/rw/* "$PM"/rw2/* 2>/dev/null
printf 'RW-OK\n' > "$PM/rw/data.txt"

# ---------------------------------------------------------------- policies
c_ro="$(cfg ro <<EOF2
[read]
$PM/ro
EOF2
)"
c_rw="$(cfg rw <<EOF2
[read]
$PM/rw
[write]
$PM/rw
EOF2
)"
c_write_only="$(cfg write_only <<EOF2
[write]
$PM/rw
EOF2
)"
c_make="$(cfg make <<EOF2
[read]
$PM/rw
[create]
$PM/rw
EOF2
)"
c_delete="$(cfg delete <<EOF2
[read]
$PM/rw
[delete]
$PM/rw
EOF2
)"
c_ipc="$(cfg ipc <<EOF2
[read]
$PM/rw
[create-ipc]
$PM/rw
EOF2
)"
c_symlink="$(cfg symlink <<EOF2
[read]
$PM/rw
[create-symlink]
$PM/rw
EOF2
)"
c_all="$(cfg all <<EOF2
[read]
$PM/rw
$PM/rw2
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
$PM/rw2
[create-symlink]
$PM/rw
$PM/rw2
EOF2
)"
c_restructure="$(cfg restructure <<EOF2
[read]
$PM/rw
$PM/rw2
[write]
$PM/rw
$PM/rw2
[restructure]
$PM/rw
$PM/rw2
EOF2
)"
c_md="$(cfg make_delete <<EOF2
[read]
$PM/rw
$PM/rw2
[create]
$PM/rw
$PM/rw2
[delete]
$PM/rw
$PM/rw2
EOF2
)"
c_exec="$(cfg exec <<EOF2
[read]
$PM/exec
[execute]
$PM/exec
EOF2
)"

echo
echo "== read =="
deny_case "a file outside every granted tree cannot be read" fs "$c_ro" open "$DENIED_ERRNOS" -- "$P" read "$PM/none/secret.txt"
allow_case "a file inside a granted tree can be read" "$c_ro" read -- "$P" read "$PM/ro/data.txt"
expect_output "and its content is the file's own" "$c_ro" "CONTENT READ-OK" -- "$P" read "$PM/ro/data.txt"
deny_case "a directory outside every granted tree cannot be listed" fs "$c_ro" opendir "$DENIED_ERRNOS" -- "$P" readdir "$PM/none"
allow_case "a directory inside a granted tree can be listed" "$c_ro" opendir -- "$P" readdir "$PM/ro"
deny_case "the parent of a granted tree cannot be listed" fs "$c_ro" opendir "$DENIED_ERRNOS" -- "$P" readdir "$PM"
deny_case "a path that climbs out of a granted tree with .. is judged where it ends" fs "$c_ro" open "$DENIED_ERRNOS" -- "$P" read "$PM/ro/../none/secret.txt"
deny_case "a relative path that climbs out of the working directory is judged where it ends" fs "$c_ro" open "$DENIED_ERRNOS" -- "$P" read "../none/secret.txt"
PREP="ln -sfn $PM/none/secret.txt $PM/ro/link-out" \
  deny_case "a symbolic link inside a granted tree to a file outside it is judged by its target" fs "$c_ro" open "$DENIED_ERRNOS" -- "$P" read "$PM/ro/link-out"
PREP="ln -sfn $PM/ro/data.txt $PM/ro/link-in" \
  allow_case "a symbolic link inside a granted tree to a file inside it works" "$c_ro" read -- "$P" read "$PM/ro/link-in"
deny_case "opening a name relative to a granted directory descriptor cannot reach outside it" fs "$c_ro" openat "$DENIED_ERRNOS" -- "$P" openat "$PM/ro" "../none/secret.txt"
c_nopath="$(cfg nopath <<EOF2
[read]
$PM/does-not-exist
EOF2
)"
run_pm --config "$c_nopath" -- "$P" read "$PM/ro/data.txt"
if ! grep -q '^START' "$PM_OUT" && (( PM_STATUS == PHB_EPOLICY )) && grep -q 'does not exist on this system' "$PM_ERR"; then ok "a policy path that does not exist is refused, since its rule would grant nothing"; else bad "a policy path that does not exist is refused, since its rule would grant nothing" "$(pm_describe)"; fi
c_file="$(cfg file <<EOF2
[read]
$PM/ro/data.txt
EOF2
)"
allow_case "a policy that names one file grants that file" "$c_file" read -- "$P" read "$PM/ro/data.txt"
printf 'OTHER\n' > "$PM/ro/other.txt"
deny_case "and not its neighbour in the same directory" fs "$c_file" open "$DENIED_ERRNOS" -- "$P" read "$PM/ro/other.txt"
mkdir -p "$PM/spaced dir/ünï"
printf 'SPACED\n' > "$PM/spaced dir/ünï/file.txt"
c_spaced="$(cfg spaced <<EOF2
[read]
$PM/spaced dir
EOF2
)"
allow_case "a path with spaces and non-ASCII letters is granted and read" "$c_spaced" read -- "$P" read "$PM/spaced dir/ünï/file.txt"
c_slash="$(cfg slash <<EOF2
[read]
$PM/ro/
EOF2
)"
allow_case "a policy path with a trailing slash grants the directory" "$c_slash" read -- "$P" read "$PM/ro/data.txt"
deny_case "a file in the same tree is denied by a policy that names only a sibling" fs "$c_slash" open "$DENIED_ERRNOS" -- "$P" read "$PM/none/secret.txt"

echo
echo "== write and truncate =="
deny_case "a file in a read-only tree cannot be opened for writing" fs "$c_ro" open "$DENIED_ERRNOS" -- "$P" open "$PM/ro/data.txt" w
allow_case "a file in a writable tree can be opened for writing" "$c_rw" open -- "$P" open "$PM/rw/data.txt" w
allow_case "and appended to" "$c_rw" open -- "$P" open "$PM/rw/data.txt" a
allow_case "and opened with O_TRUNC" "$c_rw" open -- "$P" open "$PM/rw/data.txt" trunc
deny_case "a file outside every writable tree cannot be opened for writing" fs "$c_rw" open "$DENIED_ERRNOS" -- "$P" open "$PM/none/secret.txt" w
if needs_abi 3 "truncating needs its own right"; then
  deny_case "truncate() on a file with only the read right is refused" fs "$c_ro" truncate "$DENIED_ERRNOS" -- "$P" truncate "$PM/ro/data.txt" 0
  PREP="printf 'RW-OK\n' > $PM/rw/data.txt" \
    allow_case "truncate() on a file with the write right works" "$c_rw" truncate -- "$P" truncate "$PM/rw/data.txt" 0
  PREP="printf 'RW-OK\n' > $PM/rw/data.txt" \
    allow_case "ftruncate() on a file opened for writing works" "$c_rw" ftruncate -- "$P" ftruncate "$PM/rw/data.txt" 0
fi
allow_case "a write-only policy lets the file be written" "$c_write_only" open -- "$P" open "$PM/rw/data.txt" w
deny_case "and does not let it be read" fs "$c_write_only" open "$DENIED_ERRNOS" -- "$P" read "$PM/rw/data.txt"
PREP="rm -f $PM/rw/new.txt" \
  deny_case "creating a file needs the create right, the write right is not enough" fs "$c_rw" mknod_reg "$DENIED_ERRNOS" -- "$P" mknod_reg "$PM/rw/new.txt"

echo
echo "== create, one right at a time =="
PREP="rm -f $PM/rw/new.txt" \
  allow_case "the create right makes a regular file" "$c_make" mknod_reg -- "$P" mknod_reg "$PM/rw/new.txt"
PREP="rmdir $PM/rw/newdir 2>/dev/null" \
  allow_case "the create right makes a directory" "$c_make" mkdir -- "$P" mkdir "$PM/rw/newdir"
PREP="rmdir $PM/none/newdir 2>/dev/null" \
  deny_case "and not outside its tree" fs "$c_make" mkdir "$DENIED_ERRNOS" -- "$P" mkdir "$PM/none/newdir"
PREP="rm -f $PM/rw/fifo" \
  deny_case "the create right does not make a named pipe" fs "$c_make" mkfifo "$DENIED_ERRNOS" -- "$P" mkfifo "$PM/rw/fifo"
PREP="rm -f $PM/rw/fifo" \
  allow_case "the create-ipc right makes a named pipe" "$c_ipc" mkfifo -- "$P" mkfifo "$PM/rw/fifo"
PREP="rm -f $PM/rw/sock" \
  allow_case "and a socket node" "$c_ipc" bind_unix -- "$P" mksock "$PM/rw/sock"
PREP="rm -f $PM/rw/new.txt" \
  deny_case "the create-ipc right does not make a regular file" fs "$c_ipc" mknod_reg "$DENIED_ERRNOS" -- "$P" mknod_reg "$PM/rw/new.txt"
PREP="rm -f $PM/rw/sock" \
  deny_case "the create right does not make a socket node" fs "$c_make" bind_unix "$DENIED_ERRNOS" -- "$P" mksock "$PM/rw/sock"
PREP="rm -f $PM/rw/lnk" \
  allow_case "the create-symlink right makes a symbolic link" "$c_symlink" symlink -- "$P" symlink "$PM/ro/data.txt" "$PM/rw/lnk"
PREP="rm -f $PM/rw/lnk" \
  deny_case "the create right does not make a symbolic link" fs "$c_make" symlink "$DENIED_ERRNOS" -- "$P" symlink "$PM/ro/data.txt" "$PM/rw/lnk"
PREP="rm -f $PM/rw/new.txt" \
  deny_case "the create-symlink right does not make a regular file" fs "$c_symlink" mknod_reg "$DENIED_ERRNOS" -- "$P" mknod_reg "$PM/rw/new.txt"
PREP="rm -f $PM/rw/node" \
  deny_case "a character device node is never granted, not even with every other right" fs "$c_all" mknod_char "$DENIED_ERRNOS" -- "$P" mknod_char "$PM/rw/node"
PREP="rm -f $PM/rw/node" \
  deny_case "nor a block device node" fs "$c_all" mknod_block "$DENIED_ERRNOS" -- "$P" mknod_block "$PM/rw/node"

echo
echo "== delete =="
PREP="touch $PM/rw/victim" \
  deny_case "a file cannot be deleted without the delete right" fs "$c_rw" unlink "$DENIED_ERRNOS" -- "$P" unlink "$PM/rw/victim"
PREP="touch $PM/rw/victim" \
  allow_case "a file can be deleted with the delete right" "$c_delete" unlink -- "$P" unlink "$PM/rw/victim"
PREP="touch $PM/none/victim" \
  deny_case "and not one outside the tree" fs "$c_delete" unlink "$DENIED_ERRNOS" -- "$P" unlink "$PM/none/victim"
PREP="mkdir -p $PM/rw/gone" \
  allow_case "a directory can be removed with the delete right" "$c_delete" rmdir -- "$P" rmdir "$PM/rw/gone"
PREP="mkdir -p $PM/rw/gone" \
  deny_case "and not without it" fs "$c_make" rmdir "$DENIED_ERRNOS" -- "$P" rmdir "$PM/rw/gone"
PREP="rm -f $PM/rw/old.txt $PM/rw/renamed.txt; touch $PM/rw/old.txt" \
  allow_case "a rename inside a tree needs delete and create, and works with both" "$c_md" rename -- "$P" rename "$PM/rw/old.txt" "$PM/rw/renamed.txt"
PREP="rm -f $PM/rw/old.txt $PM/rw/renamed.txt; touch $PM/rw/old.txt" \
  deny_case "a rename inside a tree is refused with delete alone" fs "$c_delete" rename "$DENIED_ERRNOS" -- "$P" rename "$PM/rw/old.txt" "$PM/rw/renamed.txt"
PREP="rm -f $PM/rw/old.txt $PM/rw/renamed.txt; touch $PM/rw/old.txt" \
  deny_case "and with create alone" fs "$c_make" rename "$DENIED_ERRNOS" -- "$P" rename "$PM/rw/old.txt" "$PM/rw/renamed.txt"

echo
echo "== moving and linking between trees (the refer right) =="
PREP="rm -f $PM/rw/m.txt $PM/rw2/m.txt; touch $PM/rw/m.txt" \
  deny_case "a rename across trees is refused without the refer right, even with delete and create" fs "$c_md" rename "EXDEV EACCES EPERM" -- "$P" rename "$PM/rw/m.txt" "$PM/rw2/m.txt"
rm -f "$PM/rw/m.txt" "$PM/rw2/m.txt"; touch "$PM/rw/m.txt"
run_pm --no-networksystem-restriction --config "$c_restructure" -- "$P" rename "$PM/rw/m.txt" "$PM/rw2/m.txt"
if op_ok rename; then ok "a rename across trees works with the restructure right, the network layer off"; else bad "a rename across trees works with the restructure right, the network layer off" "$(pm_describe)"; fi
rm -f "$PM/rw/m.txt" "$PM/rw2/m.txt"; touch "$PM/rw/m.txt"
run_pm --config "$c_restructure" -- "$P" rename "$PM/rw/m.txt" "$PM/rw2/m.txt"
if op_ok rename; then ok "a rename across trees works with the restructure right under the default layers, the network layer on"; else bad "a rename across trees works with the restructure right under the default layers" "$(pm_describe)"; fi
PREP="rm -f $PM/rw/h.txt $PM/rw/h2.txt; touch $PM/rw/h.txt" \
  allow_case "a hard link inside one directory needs only the create right" "$c_make" link -- "$P" link "$PM/rw/h.txt" "$PM/rw/h2.txt"
PREP="rm -f $PM/rw/h.txt $PM/rw2/h.txt; touch $PM/rw/h.txt" \
  deny_case "a hard link into another tree is refused without the refer right" fs "$c_md" link "EXDEV EACCES EPERM" -- "$P" link "$PM/rw/h.txt" "$PM/rw2/h.txt"
rm -f "$PM/rw/h.txt" "$PM/rw2/h.txt"; touch "$PM/rw/h.txt"
run_pm --no-networksystem-restriction --config "$c_restructure" -- "$P" link "$PM/rw/h.txt" "$PM/rw2/h.txt"
if op_ok link; then ok "a hard link into another tree works with the restructure right, the network layer off"; else bad "a hard link into another tree works with the restructure right, the network layer off" "$(pm_describe)"; fi
rm -f "$PM/rw/h.txt" "$PM/rw2/h.txt"; touch "$PM/rw/h.txt"
run_pm --config "$c_restructure" -- "$P" link "$PM/rw/h.txt" "$PM/rw2/h.txt"
if op_ok link; then ok "and so does a hard link into another tree, with every layer on"; else bad "a hard link into another tree works with the restructure right under the default layers" "$(pm_describe)"; fi
rm -f "$PM/rw/stolen.txt" "$PM/rw/h.txt" "$PM/rw2/h.txt"
PREP="rm -f $PM/rw/stolen.txt" \
  PM_EXTRA="-nnr" deny_case "a hard link to a file outside every tree, made inside a writable one, is refused" fs "$c_restructure" link "EXDEV EACCES EPERM" -- "$P" link "$PM/none/secret.txt" "$PM/rw/stolen.txt"
rm -f "$PM/rw/stolen.txt"

echo
echo "== execute =="
deny_case "a program in a tree without the execute right does not run" fs "$c_ro" exec "$DENIED_ERRNOS" -- "$P" exec "$PM/exec/pprobe-static" execd
allow_case "a program in a tree with the execute right runs" "$c_exec" exec -- "$P" exec "$PM/exec/pprobe-static" execd
c_exec_noread="$(cfg exec_noread <<EOF2
[execute]
$PM/exec
EOF2
)"
deny_case "a program in a tree with the execute right but not the read right does not run, as the kernel reads it to run it" fs "$c_exec_noread" exec "$DENIED_ERRNOS" -- "$P" exec "$PM/exec/pprobe-static" execd
deny_case "a program in another tree does not run even beside a granted one" fs "$c_exec" exec "$DENIED_ERRNOS" -- "$P" exec "$PM/none/pprobe-static" execd
cat > "$PM/ro/script.sh" <<'SCRIPT'
#!/bin/sh
echo SCRIPT-RAN
SCRIPT
chmod 0755 "$PM/ro/script.sh"
deny_case "a script in a tree without the execute right does not run" fs "$c_ro" exec "$DENIED_ERRNOS" -- "$P" exec "$PM/ro/script.sh"
allow_case "a file opened and executed by descriptor runs under the execute right" "$c_exec" fexec -- "$P" fexec "$PM/exec/pprobe-static"
deny_case "and not without it" fs "$c_ro" fexec "$DENIED_ERRNOS" -- "$P" fexec "$PM/ro/pprobe-static"

echo
echo "== what the filesystem layer does not stop, asserted as it is today =="
cp "$P" "$PM/ro/pprobe-dyn"
chmod 0755 "$PM/ro/pprobe-dyn"
loader="$(ls /lib64/ld-linux-*.so.* /lib/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -1)"
if [[ -n "$loader" ]]; then
  run_pm --config "$c_ro" -- "$P" exec "$PM/ro/pprobe-dyn" nnp_get
  direct_denied=$(op_failed_with exec $DENIED_ERRNOS; echo $?)
  run_pm --config "$c_ro" -- "$P" execld "$loader" "$PM/ro/pprobe-dyn" nnp_get
  loader_ran=$(op_ok execld && op_ok nnp_get; echo $?)
  gap_case "a program in a tree with only the read right runs when started through the dynamic loader, though not directly" "SECURITY.md" "$(( direct_denied == 0 && loader_ran == 0 ? 0 : 1 ))"
else
  skip "the dynamic loader route" "no dynamic loader found in the image"
fi
run_pm --config "$c_ro" -- "$P" memfdexec "$PM/ro/pprobe-static"
gap_case "a program copied into an anonymous memory file runs although no execute right covers it" "SECURITY.md" "$(op_ok memfdexec; echo $?)"
run_pm --config "$c_ro" -- "$P" stat "$PM/none/secret.txt"
gap_case "the existence and metadata of a path outside every tree stay visible" "what-does-phobos-not-protect-against" "$(op_ok stat; echo $?)"
printf 'x' > "$PM/ro/meta.txt"
run_pm --config "$c_ro" -- "$P" chmod "$PM/ro/meta.txt" 0600
gap_case "chmod works on a file with only the read right" "SECURITY.md" "$(op_ok chmod; echo $?)"
run_pm --config "$c_ro" -- "$P" utime "$PM/ro/meta.txt"
gap_case "utime works on a file with only the read right" "SECURITY.md" "$(op_ok utime; echo $?)"
run_pm --config "$c_ro" -- "$P" setxattr "$PM/ro/meta.txt"
setxattr_unrestricted() {
  op_ok setxattr || op_failed_with setxattr EOPNOTSUPP ENOTSUP
}
gap_case "setxattr works on a file with only the read right, or the filesystem has no extended attributes" "SECURITY.md" "$(holds_if setxattr_unrestricted)"
( exec 3< "$PM/none/secret.txt"; run_pm --config "$c_ro" -- "$P" readfd 3
  grep -q 'CONTENT TOP-SECRET' "$PM_OUT" && echo 0 > "$PM/out/gap-fd" || echo 1 > "$PM/out/gap-fd" )
gap_case "a descriptor opened before the sandbox keeps working on a file the policy does not grant" "SECURITY.md" "$(cat "$PM/out/gap-fd")"

echo
echo "== escape attempts =="
PM_EXTRA="-nnr" deny_case "a new Landlock ruleset granting everything cannot widen what is already denied" fs "$c_ro" open_after_widen "$DENIED_ERRNOS" -- "$P" landlock_widen "$PM/none/secret.txt"
run_pm -nnr --config "$c_ro" -- "$P" landlock_widen "$PM/none/secret.txt"
if op_ok landlock_create_ruleset && op_ok landlock_add_rule && op_ok landlock_restrict_self; then ok "and the second ruleset really was created, given a rule and applied, so the refusal is Landlock's and not a failed attempt"; else bad "the widening ruleset was installed" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- "$P" nnp_get
if grep -q 'OP nnp_get ret=1' "$PM_OUT"; then ok "no_new_privs is set inside the sandbox"; else bad "no_new_privs is set inside the sandbox" "$(pm_describe)"; fi
run_pm -nr -- "$P" nnp_get
if grep -q 'OP nnp_get ret=0' "$PM_OUT"; then ok "and is not set when nothing is applied (-nr)"; else bad "and is not set when nothing is applied (-nr)" "$(pm_describe)"; fi
sleep 60 &
target=$!
PM_EXTRA="-nnr" deny_case "a process outside the sandbox cannot be traced" fs "$c_ro" ptrace_attach "$DENIED_ERRNOS" -- "$P" ptrace "$target"
reap "$target"
sleep 60 &
target=$!
if needs_abi 6 "signal scoping needs Landlock 6"; then
  PM_EXTRA="-nnr" deny_case "a process outside the sandbox cannot be signalled" fs "$c_ro" kill "$DENIED_ERRNOS" -- "$P" kill "$target" 0
fi
reap "$target"
if needs_abi 6 "abstract socket scoping needs Landlock 6"; then
  "$P" abstract_server pm-outside 20 > "$PM/out/abstract.log" 2>&1 &
  server=$!
  wait_for_line "$PM/out/abstract.log" LISTENING 50
  PM_EXTRA="-nnr" deny_case "an abstract UNIX socket outside the sandbox cannot be reached" fs "$c_ro" connect_abstract "$DENIED_ERRNOS" -- "$P" abstract_connect pm-outside
  reap "$server"
  run_pm --no-networksystem-restriction --config "$c_ro" -- /bin/sh -c "$P abstract_server pm-inside 6 > /dev/null & sleep 1; $P abstract_connect pm-inside; wait"
  if op_ok connect_abstract; then ok "an abstract UNIX socket inside the same sandbox can be reached (the guard off, as it refuses every UNIX connect)"; else bad "an abstract UNIX socket inside the same sandbox can be reached" "$(pm_describe)"; fi
  run_pm --config "$c_ro" -- /bin/sh -c "$P abstract_server pm-inside2 6 > /dev/null & sleep 1; $P abstract_connect pm-inside2; wait"
  if op_failed_with connect_abstract EACCES; then ok "with the network layer on, the guard refuses even that UNIX connect"; else bad "with the network layer on, the guard refuses even that UNIX connect" "$(pm_describe)"; fi
fi
run_pm --config "$c_ro" -- "$P" nnp_get
check "the sandboxed process has no-new-privs set, which Landlock needs and which stops a setuid program raising it" "1" "$(op_result nnp_get | cut -d' ' -f1)"
run_pm --config "$c_ro" -- "$P" chroot "$PM/ro"
gap_case "chroot into a directory the policy grants works for a process that holds CAP_SYS_CHROOT, which Landlock does not restrict" "README.md of this suite, limits found, observation 5" "$(op_ok chroot; echo $?)"
deny_case "a mount is refused" fs "$c_ro" mount "$DENIED_ERRNOS" -- "$P" mount
deny_case "a new user namespace is refused" fs "$c_ro" unshare_user "$DENIED_ERRNOS" -- "$P" unshare_user

echo
echo "== children inherit the sandbox =="
run_pm --config "$c_ro" -- /bin/sh -c "$P read $PM/none/secret.txt"
if op_failed_with open $DENIED_ERRNOS; then ok "a child process cannot read what the parent cannot"; else bad "a child process cannot read what the parent cannot" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- /bin/sh -c "/bin/sh -c \"$P read $PM/none/secret.txt\""
if op_failed_with open $DENIED_ERRNOS; then ok "nor a grandchild started through another shell"; else bad "nor a grandchild started through another shell" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- /bin/sh -c "$P read $PM/ro/data.txt"
if op_ok open; then ok "and a child still reads what the policy grants"; else bad "and a child still reads what the policy grants" "$(pm_describe)"; fi

echo
echo "== preloaded libraries =="
cat > "$PM/out/preload.c" <<'PRE'
#include <fcntl.h>
#include <unistd.h>
__attribute__((constructor)) static void run(void) {
    int descriptor = open("/var/tmp/pm/rw/preload.marker", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (descriptor >= 0) {
        write(descriptor, "loaded", 6);
        close(descriptor);
    }
}
PRE
gcc-14 -shared -fPIC -o "$PM/ro/preload.so" "$PM/out/preload.c"
cp "$PM/ro/preload.so" "$PM/none/preload.so"
c_preload="$(cfg preload <<EOF2
[read]
$PM/ro
[write]
$PM/rw
[create]
$PM/rw
EOF2
)"
rm -f "$PM/rw/preload.marker"
run_direct env "LD_PRELOAD=$PM/none/preload.so" /bin/true
if [[ -f "$PM/rw/preload.marker" ]]; then
  rm -f "$PM/rw/preload.marker"
  run_pm --config "$c_preload" -- /usr/bin/env "LD_PRELOAD=$PM/ro/preload.so" /bin/true
  if [[ -f "$PM/rw/preload.marker" ]]; then ok "a preloaded library from a granted tree loads (the control for the next check)"; else bad "a preloaded library from a granted tree loads" "$(pm_describe)"; fi
  rm -f "$PM/rw/preload.marker"
  run_pm --config "$c_preload" -- /usr/bin/env "LD_PRELOAD=$PM/none/preload.so" /bin/true
  if [[ ! -f "$PM/rw/preload.marker" ]]; then ok "a preloaded library from outside every tree does not load"; else bad "a preloaded library from outside every tree does not load" "its constructor ran"; fi
else
  skip "preloaded libraries" "the control did not load the library"
fi

echo
echo "== policy edge cases =="
c_nested="$(cfg nested <<EOF2
[read]
$PM
$PM/ro
[write]
$PM
EOF2
)"
run_pm --config "$c_nested" -- "$P" read "$PM/ro/data.txt"
if (( PM_STATUS == SELF_STATUS_EPOLICY )) && ! grep -q START "$PM_OUT"; then ok "a nested entry narrower than its ancestor is refused as unenforceable, before the command starts"; else bad "a nested entry narrower than its ancestor is refused" "$(pm_describe)"; fi
c_second="$(cfg second <<EOF2
[read]
$PM/none
EOF2
)"
run_pm --config "$c_ro" --config "$c_second" -- "$P" read "$PM/none/secret.txt"
if op_ok read; then ok "two configurations are unioned: the second grants what the first does not"; else bad "two configurations are unioned" "$(pm_describe)"; fi
run_pm --config "$c_second" --config "$c_ro" -- "$P" read "$PM/ro/data.txt"
if op_ok read; then ok "in either order"; else bad "in either order" "$(pm_describe)"; fi
c_comments="$(printf '# a comment line\n[read]   \n   %s   # trailing comment\n\n' "$PM/ro" | cfg comments)"
allow_case "comments, blank lines and surrounding spaces in a policy are ignored" "$c_comments" read -- "$P" read "$PM/ro/data.txt"
c_rel="$(cfg rel <<EOF2
[read]
../../../../../../var/tmp/pm/ro
EOF2
)"
run_pm --config "$c_rel" -- "$P" read "$PM/ro/data.txt"
if ! grep -q '^START' "$PM_OUT" && (( PM_STATUS == PHB_EPOLICY )) && grep -q 'not an absolute path' "$PM_ERR"; then ok "a relative policy path with dot-dot segments is refused rather than resolved against the working directory"; else bad "a relative policy path with dot-dot segments is refused rather than resolved against the working directory" "$(pm_describe)"; fi
run_pm --config "$c_rw" -- "$P" read "$PM/none/secret.txt"
if op_failed_with open $DENIED_ERRNOS; then ok "a write grant does not grant reading elsewhere"; else bad "a write grant does not grant reading elsewhere" "$(pm_describe)"; fi

echo
echo "== an imported Ares 2 policy =="
a_ro="$(ares_cfg ares_ro "fs $PM/ro r")"
a_rw="$(ares_cfg ares_rw "fs $PM/rw rw")"
a_exec_read="$(ares_cfg ares_exec_read "fs $PM/exec r")"
a_exec="$(ares_cfg ares_exec "fs $PM/exec rx")"
a_nothing="$(ares_cfg ares_nothing "fs $PM/none -")"
allow_case "a tree granted only by an imported readAllFiles can be read" "$a_ro" read -- "$P" read "$PM/ro/data.txt"
deny_case "and a sibling the import does not name is denied" fs "$a_ro" open "$DENIED_ERRNOS" -- "$P" read "$PM/none/secret.txt"
deny_case "and the imported tree cannot be written, since overwriteAllFiles is false" fs "$a_ro" open "$DENIED_ERRNOS" -- "$P" open "$PM/ro/data.txt" w
allow_case "a tree granted an imported overwriteAllFiles can be written" "$a_rw" open -- "$P" open "$PM/rw/data.txt" w
deny_case "a program under an entry with executeAllFiles false does not run" fs "$a_exec_read" exec "$DENIED_ERRNOS" -- "$P" exec "$PM/exec/pprobe-static" execd
allow_case "and under one with executeAllFiles true it runs" "$a_exec" exec -- "$P" exec "$PM/exec/pprobe-static" execd
deny_case "an entry with every flag false grants nothing" fs "$a_nothing" open "$DENIED_ERRNOS" -- "$P" read "$PM/none/secret.txt"

finish
