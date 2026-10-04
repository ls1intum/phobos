#!/usr/bin/env bash
# The filesystem layer's edges: names that try to leave a granted tree (symbolic links, dot-dot, magic links,
# path descriptors, working directories), what a right on a file, a directory or the root does, nested and
# odd policy entries, long and strange names, the operations Landlock does not cover, and a symbolic link
# swapped while it is opened. Every denial has an unprotected control and a run with only the layer off.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${PM_HERE}/lib.sh"
pm_setup || finish
PM_ABI="$(pm_abi)"
P="$PM/bin/pprobe"
PE="$PM/bin/pedge"
cd "$PM/work" || exit 1
chmod 0777 "$PM/out" "$PM/rw"
echo "  landlock ABI ${PM_ABI}"
trap pm_restore EXIT

# Fixtures: a granted tree (ro), a writable tree (rw) and a tree that is never granted (none).
mkdir -p "$PM/ro/sub/deep" "$PM/none/sub" "$PM/rw/sub" "$PM/rw2"
printf 'DEEP\n' > "$PM/ro/sub/deep/file.txt"
printf 'INNER\n' > "$PM/none/inner.txt"
printf 'SUB\n' > "$PM/ro/sub/file.txt"
printf 'OTHER\n' > "$PM/ro/other.txt"
printf 'SCRATCH\n' > "$PM/ro/scratch.txt"
printf 'SCRATCH\n' > "$PM/ro/sub/scratch.txt"
ln -sfn "$PM/none/secret.txt" "$PM/ro/link-to-secret"
ln -sfn "$PM/none" "$PM/ro/dir-link"
ln -sfn "$PM/ro/data.txt" "$PM/ro/link-to-data"
ln -f "$PM/none/secret.txt" "$PM/ro/hard-secret"
c_ro="$(cfg ro <<EOF2
[read]
$PM/ro
EOF2
)"
c_rw="$(cfg rw <<EOF2
[read]
$PM/ro
$PM/rw
[write]
$PM/rw
[create]
$PM/rw
[delete]
$PM/rw
[create-symlink]
$PM/rw
EOF2
)"
c_proc="$(cfg proc <<EOF2
[read]
$PM/ro
/proc
EOF2
)"
# denies TITLE CONFIG -- PROBE...: the read the probe makes fails in the protected run, works in the control and
# works again with only the filesystem layer off.
denies_read() {
  local title="$1"
  local config="$2"
  shift 3
  deny_case "$title" fs "$config" open "$DENIED_ERRNOS" -- "$@"
}
# reads TITLE CONFIG EXPECTED -- PROBE...: the run reads and prints the content named.
reads() {
  local title="$1"
  local config="$2"
  local expected="$3"
  shift 4
  run_pm --config "$config" -- "$@"
  if grep -q '^START' "$PM_OUT" && grep -q "CONTENT ${expected}" "$PM_OUT"; then ok "$title"; else bad "$title" "$(pm_describe)"; fi
}

echo
echo "== symbolic links, hard links and dots =="
denies_read "a symbolic link inside a granted tree to a file outside it cannot be read through" "$c_ro" -- "$P" read "$PM/ro/link-to-secret"
denies_read "nor a symbolic link to a directory outside it" "$c_ro" -- "$P" read "$PM/ro/dir-link/secret.txt"
reads "a symbolic link to a file inside the tree can be read through" "$c_ro" "READ-OK" -- "$P" read "$PM/ro/link-to-data"
run_pm --config "$c_ro" -- "$PE" readlink "$PM/ro/link-to-secret"
if op_ok readlink && grep -q "^TARGET ${PM}/none/secret.txt" "$PM_OUT"; then ok "the text of a link in a granted tree can be read, though not what it points to"; else bad "the text of a link can be read" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- "$P" read "$PM/ro/hard-secret"
gap_case "a hard link made before the run, inside a granted tree, to a file outside it can be read, since the right follows the place in the tree" "README.md of this suite, limits found, observation 8" "$(grep -q 'CONTENT TOP-SECRET' "$PM_OUT"; echo $?)"
denies_read "dot-dot out of a granted tree is refused" "$c_ro" -- "$P" read "$PM/ro/../none/secret.txt"
denies_read "two levels down and two back up is refused too" "$c_ro" -- "$P" read "$PM/ro/sub/../../none/secret.txt"
reads "a dot in the middle of a path changes nothing" "$c_ro" "READ-OK" -- "$P" read "$PM/ro/./data.txt"
reads "nor a doubled slash" "$c_ro" "READ-OK" -- "$P" read "$PM/ro//data.txt"
reads "a file two directories down is inside the grant" "$c_ro" "DEEP" -- "$P" read "$PM/ro/sub/deep/file.txt"
run_pm --config "$c_ro" -- "$P" read "$PM/ro/data.txt/"
if op_failed_with open ENOTDIR; then ok "a trailing slash on a file is ENOTDIR, which says nothing beyond the grant"; else bad "a trailing slash on a file is ENOTDIR" "$(pm_describe)"; fi

echo
echo "== the newer open call and its flags =="
reads "openat2 with no flags reads a granted file" "$c_ro" "READ-OK" -- "$PE" openat2 "$PM/ro/data.txt" r 0
deny_case "openat2 on a file outside every tree is refused" fs "$c_ro" openat2 "$DENIED_ERRNOS" -- "$PE" openat2 "$PM/none/secret.txt" r 0
deny_case "openat2 through a link to a forbidden file is refused" fs "$c_ro" openat2 "$DENIED_ERRNOS" -- "$PE" openat2 "$PM/ro/link-to-secret" r 0
run_pm --config "$c_ro" -- "$PE" openat2 "$PM/ro/link-to-secret" r 0x4
if op_failed_with openat2 ELOOP; then ok "openat2 told not to follow links stops at the link, with ELOOP"; else bad "openat2 with no symlinks stops at the link" "$(pm_describe)"; fi
reads "openat2 told not to follow links still reads a plain file" "$c_ro" "READ-OK" -- "$PE" openat2 "$PM/ro/data.txt" r 0x4
run_pm --config "$c_ro" -- "$PE" openat2 "$PM/ro/data.txt" r 0x8
if op_failed_with openat2 EXDEV; then ok "openat2 told to stay beneath its directory refuses an absolute path, with EXDEV"; else bad "openat2 beneath refuses an absolute path" "$(pm_describe)"; fi

echo
echo "== directories held open and the working directory =="
reads "a path descriptor of a granted directory opens a file inside it" "$c_ro" "READ-OK" -- "$PE" dirfd_open "$PM/ro" data.txt
run_pm --config "$c_ro" -- "$PE" dirfd_open "$PM/none" secret.txt
if op_failed_with openat_relative $DENIED_ERRNOS && ! grep -q 'TOP-SECRET' "$PM_OUT"; then ok "a path descriptor of a forbidden directory opens nothing inside it"; else bad "a path descriptor of a forbidden directory opens nothing" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- "$PE" dirfd_open "$PM/ro" ../none/secret.txt
if op_failed_with openat_relative $DENIED_ERRNOS && ! grep -q 'TOP-SECRET' "$PM_OUT"; then ok "a path descriptor of a granted directory cannot reach out of it with dot-dot"; else bad "a path descriptor cannot reach out with dot-dot" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- "$PE" chdir_open "$PM/ro" data.txt
if op_ok chdir && op_ok open_relative; then ok "moving into a granted directory and opening a relative name works"; else bad "chdir into a granted directory and a relative open" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- "$PE" chdir_open "$PM/none" secret.txt
if op_ok chdir && op_failed_with open_relative $DENIED_ERRNOS; then ok "moving into a forbidden directory is allowed, and opening inside it is not"; else bad "chdir into a forbidden directory opens nothing" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- "$PE" chdir_open "$PM/ro" ../none/secret.txt
if op_failed_with open_relative $DENIED_ERRNOS; then ok "a relative dot-dot from a granted working directory is refused"; else bad "a relative dot-dot out of the working directory is refused" "$(pm_describe)"; fi

echo
echo "== magic links under /proc =="
run_pm --config "$c_proc" -- "$P" read "/proc/self/root${PM}/none/secret.txt"
if op_failed_with open $DENIED_ERRNOS; then ok "the root seen through /proc does not reach a file outside every tree"; else bad "/proc/self/root does not reach a forbidden file" "$(pm_describe)"; fi
reads "and it reaches a granted file as the same path would" "$c_proc" "READ-OK" -- "$P" read "/proc/self/root${PM}/ro/data.txt"
run_pm --config "$c_ro" -- "$P" read /proc/self/status
if op_failed_with open $DENIED_ERRNOS; then ok "without a grant /proc is closed"; else bad "without a grant /proc is closed" "$(pm_describe)"; fi
( exec 7< "$PM/none/secret.txt"; run_pm --config "$c_proc" -- "$P" read /proc/self/fd/7 )
if op_failed_with open $DENIED_ERRNOS; then ok "reopening a descriptor to a forbidden file through /proc checks the file, and is refused"; else bad "reopening a forbidden descriptor through /proc is refused" "$(pm_describe)"; fi
( exec 7< "$PM/none/secret.txt"; run_pm --config "$c_proc" -- "$P" readfd 7 )
gap_case "while the descriptor itself, opened before the sandbox, still reads the same file" "SECURITY.md" "$(grep -q 'CONTENT TOP-SECRET' "$PM_OUT"; echo $?)"

echo
echo "== unnamed files =="
run_pm --config "$c_rw" -- "$PE" otmpfile "$PM/rw"
if op_ok otmpfile; then ok "an unnamed file can be made where files can be created"; else bad "an unnamed file can be made where files can be created" "$(pm_describe)"; fi
deny_case "and not where they cannot" fs "$c_rw" otmpfile "$DENIED_ERRNOS" -- "$PE" otmpfile "$PM/ro"
deny_case "nor outside every tree" fs "$c_rw" otmpfile "$DENIED_ERRNOS" -- "$PE" otmpfile "$PM/none"

echo
echo "== what Landlock does not cover, asserted as it is =="
for call in getxattr listxattr lstat statx; do
  run_pm --config "$c_ro" -- "$PE" "$call" "$PM/none/secret.txt"
  gap_case "${call} works on a file outside every tree" "what-does-phobos-not-protect-against" "$(op_ok "$call"; echo $?)"
done
run_pm --config "$c_ro" -- "$PE" inotify "$PM/none/secret.txt"
gap_case "a watch for changes can be placed on a file outside every tree" "README.md of this suite, limits found, observation 8" "$(op_ok inotify_add_watch; echo $?)"
for mode in sendfile splice copy_file_range; do
  rm -f "$PM/rw/out"
  ( exec 7< "$PM/none/secret.txt"; run_pm --config "$c_rw" -- "$PE" fdcopy "$mode" 7 "$PM/rw/out" )
  gap_case "${mode} copies a descriptor opened before the sandbox into a writable tree" "SECURITY.md" "$(op_ok "$mode" && [[ "$(cat "$PM/rw/out" 2> /dev/null)" == "TOP-SECRET"* ]]; echo $?)"
done
( exec 7< "$PM/none/secret.txt"; run_pm --config "$c_rw" -- "$PE" fdcopy mmap 7 "$PM/rw/out" )
gap_case "and a descriptor opened before the sandbox can be mapped and read" "SECURITY.md" "$(grep -q 'MAPPED TOP-SECRET' "$PM_OUT"; echo $?)"
run_pm --config "$c_ro" -- "$P" read "$PM/none/nonexistent"
missing_answer="$(op_result open | cut -d' ' -f2)"
run_pm --config "$c_ro" -- "$P" read "$PM/none/secret.txt"
existing_answer="$(op_result open | cut -d' ' -f2)"
if [[ "$missing_answer" == ENOENT && "$existing_answer" == EACCES ]]; then ok "opening a name outside every tree answers ENOENT when it is missing and EACCES when it exists, so existence is visible"; else bad "open answers differently for a missing and an existing name" "missing ${missing_answer}, existing ${existing_answer}"; fi
run_pm --config "$c_ro" -- "$P" stat "$PM/none/nonexistent"
missing_answer="$(op_result stat | cut -d' ' -f2)"
run_pm --config "$c_ro" -- "$P" stat "$PM/none/secret.txt"
if [[ "$missing_answer" == ENOENT ]] && op_ok stat; then ok "and stat succeeds on the existing name and answers ENOENT on the missing one"; else bad "stat answers differently for a missing and an existing name" "missing ${missing_answer}: $(pm_describe)"; fi

echo
echo "== the answer a refusal gives =="
run_pm --config "$c_ro" -- "$P" unlink "$PM/ro/nonexistent"
if op_failed_with unlink ENOENT; then ok "deleting a missing name in a read-only tree is ENOENT"; else bad "deleting a missing name is ENOENT" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- "$P" unlink "$PM/ro/data.txt"
if op_failed_with unlink EACCES; then ok "deleting an existing file in a read-only tree is EACCES"; else bad "deleting an existing file is EACCES" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- "$P" mkdir "$PM/ro/sub"
if op_failed_with mkdir EEXIST; then ok "making a directory that exists is EEXIST, not a refusal"; else bad "mkdir on an existing directory is EEXIST" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- "$P" mkdir "$PM/ro/newdir"
if op_failed_with mkdir EACCES; then ok "making a new one is EACCES"; else bad "mkdir of a new directory is EACCES" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- "$P" symlink x "$PM/ro/newlink"
if op_failed_with symlink EACCES; then ok "making a symbolic link in a read-only tree is EACCES"; else bad "a symbolic link in a read-only tree is EACCES" "$(pm_describe)"; fi
run_pm --config "$c_ro" -- "$P" open "$PM/none/secret.txt" w
if op_failed_with open EACCES; then ok "opening a forbidden file for writing is EACCES"; else bad "opening a forbidden file for writing is EACCES" "$(pm_describe)"; fi

echo
echo "== devices =="
run_pm --config "$c_ro" -- "$P" open /dev/null r
if op_ok open; then ok "/dev/null is granted by the base policy and opens"; else bad "/dev/null opens" "$(pm_describe)"; fi
for device in /dev/zero /dev/urandom /dev/full; do
  deny_case "${device} is closed unless a policy names it" fs "$c_ro" open "$DENIED_ERRNOS" -- "$P" open "$device" r
done

echo
echo "== what a right does on a file, on a directory and on the root =="
c_file="$(cfg onefile <<EOF2
[read]
$PM/ro/data.txt
EOF2
)"
reads "a read grant on one file reads that file" "$c_file" "READ-OK" -- "$P" read "$PM/ro/data.txt"
deny_case "and not its sibling" fs "$c_file" open "$DENIED_ERRNOS" -- "$P" read "$PM/ro/other.txt"
deny_case "and the directory around it cannot be listed" fs "$c_file" opendir "$DENIED_ERRNOS" -- "$P" readdir "$PM/ro"
c_wfile="$(cfg writefile <<EOF2
[read]
$PM/ro
[write]
$PM/rw/data.txt
EOF2
)"
run_pm --config "$c_wfile" -- "$P" write "$PM/rw/data.txt" CHANGED
if op_ok write; then ok "a write grant on one file writes that file"; else bad "a write grant on one file writes it" "$(pm_describe)"; fi
printf 'RW-OK\n' > "$PM/rw/data.txt"
PREP="rm -f $PM/rw/new.txt" deny_case "and creates nothing beside it" fs "$c_wfile" open "$DENIED_ERRNOS" -- "$P" write "$PM/rw/new.txt" X
rm -f "$PM/rw/new.txt"
run_pm --config "$c_wfile" -- "$P" write "$PM/rw/new.txt" X
if [[ ! -e "$PM/rw/new.txt" ]]; then ok "and the new file is not there afterwards"; else bad "the new file is not created" "it exists"; fi
c_root="$(cfg rootread <<EOF2
[read]
/
EOF2
)"
reads "a read grant on the root reads a file outside every other tree" "$c_root" "TOP-SECRET" -- "$P" read "$PM/none/secret.txt"
PREP="rm -f $PM/rw/new.txt" deny_case "but a read grant on the root writes nothing" fs "$c_root" open "$DENIED_ERRNOS" -- "$P" write "$PM/rw/new.txt" X
c_nested="$(cfg nested <<EOF2
[read]
$PM/ro
[write]
$PM/ro/sub
EOF2
)"
run_pm --config "$c_nested" -- "$P" write "$PM/ro/sub/scratch.txt" CHANGED
if op_ok write; then ok "a write grant under a read grant writes a file in the inner tree"; else bad "a write grant under a read grant writes there" "$(pm_describe)"; fi
printf 'SCRATCH\n' > "$PM/ro/sub/scratch.txt"
deny_case "and not a file in the outer one" fs "$c_nested" open "$DENIED_ERRNOS" -- "$P" write "$PM/ro/scratch.txt" X
printf 'SCRATCH\n' > "$PM/ro/scratch.txt"
c_inner_only="$(cfg innerread <<EOF2
[read]
$PM/ro/sub
EOF2
)"
reads "a read grant on only the inner tree reads there" "$c_inner_only" "SUB" -- "$P" read "$PM/ro/sub/file.txt"
deny_case "and not in the tree around it" fs "$c_inner_only" open "$DENIED_ERRNOS" -- "$P" read "$PM/ro/data.txt"
c_narrower="$(cfg narrower <<EOF2
[read]
$PM/ro
[execute]
$PM/ro
[read]
$PM/ro/sub
EOF2
)"
run_pm --config "$c_narrower" -- "$P" cwd
if ! grep -q '^START' "$PM_OUT" && (( PM_STATUS == PHB_EPOLICY )); then ok "an inner entry with fewer rights than the one around it is refused as unenforceable, since Landlock cannot take a right away"; else bad "a narrower inner entry is refused as unenforceable" "$(pm_describe)"; fi
c_wider="$(cfg wider <<EOF2
[read]
$PM/ro
$PM/ro/sub
[execute]
$PM/ro/sub
EOF2
)"
run_pm --config "$c_wider" -- "$P" read "$PM/ro/sub/file.txt"
if grep -q 'CONTENT SUB' "$PM_OUT"; then ok "an inner entry with more rights than the one around it is accepted"; else bad "a wider inner entry is accepted" "$(pm_describe)"; fi

echo
echo "== strange and long names =="
mkdir -p "$PM/odd/with space" "$PM/odd/ünï" "$PM/odd/-dash" "$PM/odd/hash#x" "$PM/odd/dot.dir"
for name in "with space" "ünï" "-dash" "hash#x" "dot.dir"; do
  printf 'ODD-%s\n' "${name%% *}" > "$PM/odd/${name}/f.txt"
done
for name in "with space" "ünï" "-dash" "dot.dir"; do
  printf '[read]\n%s/odd/%s\n' "$PM" "$name" > "$PM/cfg/odd.cfg"
  reads "a directory named '${name}' can be granted and read" "$PM/cfg/odd.cfg" "ODD-${name%% *}" -- "$P" read "$PM/odd/${name}/f.txt"
done
printf '[read]\n%s/odd/hash#x\n' "$PM" > "$PM/cfg/odd.cfg"
deny_case "a directory with a hash in its name cannot be granted, since the rest of the line is a comment" fs "$PM/cfg/odd.cfg" open "$DENIED_ERRNOS" -- "$P" read "$PM/odd/hash#x/f.txt"
long_name="$(printf 'n%.0s' $(seq 1 255))"
printf 'LONG\n' > "$PM/ro/$long_name"
reads "a file name of 255 characters is the longest there is, and is readable" "$c_ro" "LONG" -- "$P" read "$PM/ro/$long_name"
run_pm --config "$c_ro" -- "$P" read "$PM/ro/${long_name}n"
if op_failed_with open EOTHER; then ok "and one of 256 characters is refused for its length, not for the sandbox"; else bad "a name of 256 characters is too long" "$(pm_describe)"; fi
deep="$PM/ro"
for level in $(seq 1 60); do
  deep="${deep}/d${level}"
done
mkdir -p "$deep"
printf 'BOTTOM\n' > "$deep/file.txt"
reads "a file sixty directories down is inside the grant" "$c_ro" "BOTTOM" -- "$P" read "$deep/file.txt"

echo
echo "== the policy file's own spellings of a path =="
ln -sfn "$PM/ro" "$PM/link-ro"
printf '[read]\n%s\n' "$PM/link-ro" > "$PM/cfg/spell.cfg"
reads "a symbolic link as the policy entry grants the directory it points to" "$PM/cfg/spell.cfg" "READ-OK" -- "$P" read "$PM/ro/data.txt"
printf '[read]\n%s/\n' "$PM/ro" > "$PM/cfg/spell.cfg"
reads "a trailing slash on the entry changes nothing" "$PM/cfg/spell.cfg" "READ-OK" -- "$P" read "$PM/ro/data.txt"
printf '[read]\n%s//ro\n' "$PM" > "$PM/cfg/spell.cfg"
reads "a doubled slash in the entry changes nothing" "$PM/cfg/spell.cfg" "READ-OK" -- "$P" read "$PM/ro/data.txt"
printf '[read]\n%s/ro/./sub/..\n' "$PM" > "$PM/cfg/spell.cfg"
reads "dot and dot-dot in the entry are resolved first" "$PM/cfg/spell.cfg" "READ-OK" -- "$P" read "$PM/ro/data.txt"
ln -sfn "$PM/none/does-not-exist" "$PM/dangling"
printf '[read]\n%s\n%s\n' "$PM/ro" "$PM/dangling" > "$PM/cfg/spell.cfg"
run_pm --config "$PM/cfg/spell.cfg" -- "$P" read "$PM/ro/data.txt"
if grep -q 'CONTENT READ-OK' "$PM_OUT"; then ok "an entry that is a dangling link is skipped and grants nothing"; else bad "a dangling link entry is skipped" "$(pm_describe)"; fi
printf '[read]\n%s\n' "$PM/ro/link-to-data" > "$PM/cfg/spell.cfg"
reads "an entry that is a link to a file grants that file" "$PM/cfg/spell.cfg" "READ-OK" -- "$P" read "$PM/ro/data.txt"

echo
echo "== moving files, with the right to move them =="
c_move="$(cfg move <<EOF2
[read]
$PM/ro
[restructure]
$PM/rw
$PM/rw2
[write]
$PM/rw
$PM/rw2
EOF2
)"
printf 'M\n' > "$PM/rw/m1.txt"
printf 'N\n' > "$PM/rw/m2.txt"
run_pm --config "$c_move" -- "$P" renameat2_exchange "$PM/rw/m1.txt" "$PM/rw/m2.txt"
if op_ok renameat2_exchange; then ok "two files in one tree can be exchanged"; else bad "an exchange inside one tree" "$(pm_describe)"; fi
printf 'M\n' > "$PM/rw/m1.txt"
printf 'N\n' > "$PM/rw2/m2.txt"
run_pm --config "$c_move" -- "$P" renameat2_exchange "$PM/rw/m1.txt" "$PM/rw2/m2.txt"
if op_ok renameat2_exchange; then ok "and across two trees that both grant moving"; else bad "an exchange across trees with the right to move" "$(pm_describe)"; fi
printf 'M\n' > "$PM/rw/m1.txt"
printf 'N\n' > "$PM/rw/m2.txt"
run_pm --config "$c_move" -- "$P" renameat2_noreplace "$PM/rw/m1.txt" "$PM/rw/m2.txt"
if op_failed_with renameat2_noreplace EEXIST; then ok "a rename that must not replace stops at an existing name with EEXIST"; else bad "a no-replace rename stops at an existing name" "$(pm_describe)"; fi
rm -f "$PM/rw/m3.txt"
run_pm --config "$c_move" -- "$P" renameat2_noreplace "$PM/rw/m1.txt" "$PM/rw/m3.txt"
if op_ok renameat2_noreplace; then ok "and succeeds at a new one"; else bad "a no-replace rename to a new name" "$(pm_describe)"; fi
printf 'M\n' > "$PM/rw/m1.txt"
printf 'N\n' > "$PM/rw2/m2.txt"
deny_case "an exchange across trees is refused when only one of them grants moving" fs "$(printf '[read]\n%s\n[restructure]\n%s\n[write]\n%s\n%s\n' "$PM/ro" "$PM/rw" "$PM/rw" "$PM/rw2" | cfg halfmove)" renameat2_exchange "EXDEV EACCES EPERM" -- "$P" renameat2_exchange "$PM/rw/m1.txt" "$PM/rw2/m2.txt"
run_pm --config "$c_move" -- "$P" rmdir "$PM/rw/sub"
if op_ok rmdir; then ok "an empty directory can be removed where deleting is granted"; else bad "an empty directory can be removed" "$(pm_describe)"; fi
mkdir -p "$PM/rw/full"
printf 'x\n' > "$PM/rw/full/f"
run_pm --config "$c_move" -- "$P" rmdir "$PM/rw/full"
if op_failed_with rmdir ENOTEMPTY; then ok "and a full one is ENOTEMPTY, which is the kernel's answer and not the sandbox's"; else bad "a full directory is ENOTEMPTY" "$(pm_describe)"; fi

echo
echo "== a symbolic link swapped while it is opened =="
race_round=0
first_swaps=""
second_swaps=""
# Whether the thread really pointed the link at both files during the protected run, 100 times each at least.
swaps_ran() {
  first_swaps="$(sed -n 's/.*installed_first=\([0-9]*\).*/\1/p' "$PM_OUT")"
  second_swaps="$(sed -n 's/.*installed_second=\([0-9]*\).*/\1/p' "$PM_OUT")"
  [[ -n "$first_swaps" && -n "$second_swaps" ]] && (( first_swaps >= 100 && second_swaps >= 100 ))
}
for attempts in 20000 20000 20000; do
  race_round=$(( race_round + 1 ))
  rm -f "$PM/rw/race-link" "$PM/rw/race-link.tmp"
  run_direct "$PE" open_race "$PM/rw/race-link" "$PM/ro/data.txt" "$PM/none/secret.txt" "$attempts"
  control_secret="$(sed -n 's/.*secret=\([0-9]*\).*/\1/p' "$PM_OUT")"
  rm -f "$PM/rw/race-link" "$PM/rw/race-link.tmp"
  run_pm --config "$c_rw" -- "$PE" open_race "$PM/rw/race-link" "$PM/ro/data.txt" "$PM/none/secret.txt" "$attempts"
  secret="$(sed -n 's/.*secret=\([0-9]*\).*/\1/p' "$PM_OUT")"
  allowed="$(sed -n 's/.*allowed=\([0-9]*\).*/\1/p' "$PM_OUT")"
  if [[ -n "$secret" && "$secret" -gt 0 ]]; then
    bad "a link swapped while it is opened never gives the forbidden file (round ${race_round})" "the protected run read the forbidden file ${secret} times, the control ${control_secret:-none}: $(pm_describe)"
  elif [[ -z "$control_secret" || "$control_secret" -le 0 ]]; then
    skip "a link swapped while it is opened never gives the forbidden file (round ${race_round})" "without Phobos the swap never gave the forbidden file either, so the race cannot be reached here"
  elif [[ "$secret" == 0 && -n "$allowed" && "$allowed" -gt 0 ]] && ! swaps_ran; then
    skip "a link swapped while it is opened never gives the forbidden file (round ${race_round})" "the swapping thread installed the links only ${first_swaps:-0} and ${second_swaps:-0} times in the protected run, too few to call the race reached"
  elif [[ "$secret" == 0 && -n "$allowed" && "$allowed" -gt 0 ]]; then
    ok "a link swapped while it is opened never gives the forbidden file, and the allowed one is still read (round ${race_round}, ${first_swaps} and ${second_swaps} swaps, the control read it ${control_secret} times)"
  else
    bad "a link swapped while it is opened never gives the forbidden file (round ${race_round})" "control ${control_secret}; protected: secret ${secret:-none}, allowed ${allowed:-none}, swaps ${first_swaps:-none}/${second_swaps:-none}: $(pm_describe)"
  fi
done

finish
