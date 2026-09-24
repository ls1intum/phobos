#!/usr/bin/env bash
# Tests how build_path_args turns a policy's filesystem sections into Landlock path rules.
#
# Landlock unions the rights of every rule along a path and can never take one away, so a
# nested entry granting strictly fewer rights than an ancestor states a restriction that
# would not hold, and resolve_rights_hierarchy refuses it. Two other shapes are deliberately
# allowed: an entry whose rights an ancestor already covers, and one whose rights are merely
# different rather than narrower. The difference between those three decides which exercise
# configurations Phobos accepts at all, and nothing measured it before this suite.
#
# It also pins the consequence AGENTS.md records: an entry a base policy names redundantly
# is what lets an exercise configuration name that same path with fewer rights. Deleting the
# redundant entry as a tidy-up turns an accepted configuration into a refused run.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../core"
# shellcheck source=../../core/phobos-tools-common/phobos-constants.sh
source "${CORE}/phobos-tools-common/phobos-constants.sh"
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# The tree the policies below name. Real directories, because build_path_args drops a read or
# execute path that does not exist and would otherwise silently prove nothing.
TREE="$WORK/tree"
mkdir -p "$TREE/child" "$TREE/other"
# A second spelling of the same tree, as /bin is of /usr/bin in the run-phase image.
ALIAS="$WORK/alias"
ln -s "$TREE" "$ALIAS"

# Runs build_path_args over one section body per right in a subshell, so a policy refusal
# (which exits) is captured rather than ending this suite. Each argument is the body of the
# section named in the order read, execute, write, create, delete; an empty one writes no
# paths. Every line is terminated, as parse_cfg_policy terminates the ones it writes, because
# collect_rights_table reads with a plain `while read` and an unterminated last line is lost.
# Prints "<exit>|<args>|<log>".
run_sections() {
  local right
  local index=1
  for right in read execute write create delete ipc symlink refer; do
    if [[ -n "${!index:-}" ]]; then printf '%s\n' "${!index}" > "$WORK/${right}.paths"; else : > "$WORK/${right}.paths"; fi
    index=$((index + 1))
  done
  local out
  out="$(
    export PHOBOS_SCRATCH="$WORK/scratch"
    mkdir -p "$PHOBOS_SCRATCH"
    # shellcheck source=../../core/phobos-tools-common/phobos-common.sh
    source "${CORE}/phobos-tools-common/phobos-common.sh"
    args=()
    build_path_args args "$WORK/read.paths" "$WORK/execute.paths" "$WORK/write.paths" \
      "$WORK/create.paths" "$WORK/delete.paths" "$WORK/ipc.paths" "$WORK/symlink.paths" \
      "$WORK/refer.paths" 2>"$WORK/log"
    printf '%s' "${args[*]}"
  )"
  local rc=$?
  printf '%s|%s|%s' "$rc" "$out" "$(tr '\n' ' ' <"$WORK/log")"
}

field() { cut -d'|' -f"$2" <<<"$1"; }

echo "== a nested entry narrower than its ancestor is refused =="
r="$(run_sections "$TREE
$TREE/child" "$TREE" "" "" "")"
if [[ "$(field "$r" 1)" == "$PHB_EPOLICY" && "$(field "$r" 3)" == *"Policy unenforceable"* ]]; then
  ok "read beneath read+execute ends the run with PHB-EPOLICY"
else
  bad "read beneath read+execute ends the run with PHB-EPOLICY" \
    "exit ${PHB_EPOLICY} and a 'Policy unenforceable' report" "exit $(field "$r" 1): $(field "$r" 3)"
fi

echo
echo "== the same entry is accepted once the ancestor's rights are also named on it =="
r="$(run_sections "$TREE
$TREE/child" "$TREE
$TREE/child" "" "" "")"
if [[ "$(field "$r" 1)" == 0 && "$(field "$r" 2)" == *"--rights=rx ${TREE}/child"* ]]; then
  ok "read+execute beneath read+execute is allowed and keeps its own rule"
else
  bad "read+execute beneath read+execute is allowed and keeps its own rule" \
    "exit 0 and a --rights=rx rule for the child" "exit $(field "$r" 1): $(field "$r" 2)"
fi

echo
echo "== an entry whose rights are different rather than narrower is allowed =="
r="$(run_sections "$TREE" "$TREE" "$TREE/child" "" "")"
if [[ "$(field "$r" 1)" == 0 && "$(field "$r" 2)" == *"--rights=rwx ${TREE}/child"* ]]; then
  ok "a writable workspace beneath a read+execute tree holds the union"
else
  bad "a writable workspace beneath a read+execute tree holds the union" \
    "exit 0 and a --rights=rwx rule for the child" "exit $(field "$r" 1): $(field "$r" 2)"
fi

echo
echo "== a redundant base entry is what lets an exercise name that path with fewer rights =="
# This one goes through the real merge rather than through hand-written section files:
# phobos-policysystem.sh folds a base configuration and an exercise configuration into one
# specification, and the filesystem layer then builds the rules from it. Feeding
# build_path_args an already-unioned set would prove nothing about that fold.
#
# Takes "yes" or "no" for whether the base names the child beside its ancestor, and prints
# the exit status of building the path arguments from the specification the two produce.
run_composed() {
  local base_names_the_child="$1"
  local work
  work="$(mktemp -d -p "$WORK")"
  mkdir -p "$work/core"
  cp "$CORE"/*.sh "$work/core/"
  # The layer scripts source their helpers from the phobos-tools-* folders, so the minimal core
  # copy needs those folders too, not only the top-level scripts.
  cp -R "$CORE"/phobos-tools-* "$work/core/"
  {
    printf '[read]\n%s\n' "$TREE"
    [[ "$base_names_the_child" == yes ]] && printf '%s\n' "$TREE/child"
    printf '[execute]\n%s\n' "$TREE"
    [[ "$base_names_the_child" == yes ]] && printf '%s\n' "$TREE/child"
  } > "$work/core/BaseProbe.cfg"
  printf '[read]\n%s\n' "$TREE/child" > "$work/exercise.cfg"
  local spec="$work/spec"
  mkdir -p "$spec"
  bash "$work/core/phobos-policysystem.sh" --spec-dir "$spec" --config "$work/exercise.cfg" \
    >/dev/null 2>&1 || { printf 'policy:%s' "$?"; return 0; }
  (
    export PHOBOS_SCRATCH="$spec/scratch"
    mkdir -p "$PHOBOS_SCRATCH"
    # shellcheck source=../../core/phobos-tools-common/phobos-common.sh
    source "${CORE}/phobos-tools-common/phobos-common.sh"
    args=()
    build_path_args args "$spec/read.paths" "$spec/execute.paths" "$spec/write.paths" \
      "$spec/create.paths" "$spec/delete.paths" "$spec/ipc.paths" "$spec/symlink.paths" \
      "$spec/refer.paths" >/dev/null 2>&1
  )
  printf '%s' "$?"
}

base_keeps_it="$(run_composed yes)"
base_drops_it="$(run_composed no)"
if [[ "$base_keeps_it" == 0 && "$base_drops_it" == "$PHB_EPOLICY" ]]; then
  ok "deleting the redundant base entry turns an accepted policy into PHB-EPOLICY"
else
  bad "deleting the redundant base entry turns an accepted policy into PHB-EPOLICY" \
    "0 with the entry and ${PHB_EPOLICY} without it" "${base_keeps_it} and ${base_drops_it}"
fi

echo
echo "== a redundant entry does not make any other narrower subpath acceptable =="
r="$(run_sections "$TREE
$TREE/child
$TREE/other" "$TREE
$TREE/child" "" "" "")"
if [[ "$(field "$r" 1)" == "$PHB_EPOLICY" ]]; then
  ok "a sibling named with fewer rights is still refused"
else
  bad "a sibling named with fewer rights is still refused" \
    "exit ${PHB_EPOLICY}" "exit $(field "$r" 1): $(field "$r" 2)"
fi

echo
echo "== two spellings of one tree fold together and each still gets a rule =="
# /bin is a symbolic link to /usr/bin in the run-phase image, so one tree can be named twice.
# Landlock anchors a rule on the inode, so the two rows are one target: the rights are
# unioned across them, and each spelling still needs a rule of its own or one of them would
# silently be dropped.
r="$(run_sections "$TREE
$ALIAS" "$ALIAS" "" "" "")"
rules="$(field "$r" 2)"
if [[ "$(field "$r" 1)" == 0 && "$rules" == *"--rights=rx ${TREE}"* && "$rules" == *"--rights=rx ${ALIAS}"* ]]; then
  ok "a path and a symbolic link to it hold the union, and both spellings keep a rule"
else
  bad "a path and a symbolic link to it hold the union, and both spellings keep a rule" \
    "exit 0 and an rx rule for each spelling" "exit $(field "$r" 1): $rules"
fi

echo
echo "== the new create buckets each grant exactly their own letter =="
r="$(run_sections "" "" "" "" "" "$TREE" "" "")"
if [[ "$(field "$r" 1)" == 0 && "$(field "$r" 2)" == "--rights=p ${TREE}" ]]; then
  ok "a [create-ipc] path grants only p"
else
  bad "a [create-ipc] path grants only p" "exit 0 and --rights=p ${TREE}" "exit $(field "$r" 1): $(field "$r" 2)"
fi

r="$(run_sections "" "" "" "" "" "" "$TREE" "")"
if [[ "$(field "$r" 1)" == 0 && "$(field "$r" 2)" == "--rights=l ${TREE}" ]]; then
  ok "a [create-symlink] path grants only l"
else
  bad "a [create-symlink] path grants only l" "exit 0 and --rights=l ${TREE}" "exit $(field "$r" 1): $(field "$r" 2)"
fi

r="$(run_sections "" "" "" "" "" "" "" "$TREE")"
if [[ "$(field "$r" 1)" == 0 && "$(field "$r" 2)" == "--rights=f ${TREE}" ]]; then
  ok "a refer path grants only f"
else
  bad "a refer path grants only f" "exit 0 and --rights=f ${TREE}" "exit $(field "$r" 1): $(field "$r" 2)"
fi

echo
echo "== [restructure] gives a path create, delete and refer together =="
# parse_cfg_policy sends a [restructure] path into the create, delete and refer buckets, so the
# path holds m, d and f together: it may create, delete, and rename or move across directories.
# A path named in several buckets yields one rule per bucket, all with the same unioned rights,
# exactly as a path in both [create] and [delete] does today; Landlock unions them harmlessly.
r="$(run_sections "" "" "" "$TREE" "$TREE" "" "" "$TREE")"
if [[ "$(field "$r" 1)" == 0 && "$(field "$r" 2)" == *"--rights=mfd ${TREE}"* ]]; then
  ok "a path in create, delete and refer holds m, d and f"
else
  bad "a path in create, delete and refer holds m, d and f" \
    "exit 0 and a --rights=mfd rule for ${TREE}" "exit $(field "$r" 1): $(field "$r" 2)"
fi

finish
