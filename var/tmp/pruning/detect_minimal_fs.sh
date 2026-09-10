#!/usr/bin/env bash
# detect_minimal_fs.sh – language-agnostic pruning; API unchanged.
set -euo pipefail

# ── logging ──────────────────────────────────────────────────────────────────
err()   { echo -e "\e[31m[error]\e[0m $*" >&2; exit 1; }
warn()  { echo -e "\e[33m[warn]\e[0m  $*" >&2; }
# return 0, because without it the && returns 1 whenever logging is off and set -e
# ends the run at the first call. run_minimal_fs_all.sh carried the same defect: a
# prune without --verbose could never get past its first log line.
log()   { [[ "${LOG_ENABLED:-0}" -eq 1 ]] && echo "[LOG] $*"; return 0; }
error() { err "$@"; }

# returns 0 if $1 has prefix of any subsequent args
# Whether a path is one of the listed ones, or lives under it. By path component, not
# by prefix: a child named /proc-secret is not the /proc pseudo-filesystem, and treating
# it as one silently excludes it from the prune.
is_in_list() { local p=$1; shift; for x; do [[ $p == "$x" || $p == "$x"/* ]] && return 0; done; return 1; }

# ── CLI / defaults ───────────────────────────────────────────────────────────
TARGET=""
BUILD_SCRIPT="/bin/true"
EXPLICIT_ENV=()
TEST_DIR=""
ASSIGN_DIR=""
LOG_ENABLED=0
LANG=""

IGNORABLE_FAILURE_PATTERNS=${IGNORABLE_FAILURE_PATTERNS:-"There were failing tests|> Task :(compileJava|compileTestJava) NO-SOURCE"}
UNIGNORABLE_SUCCESS_PATTERNS=${UNIGNORABLE_SUCCESS_PATTERNS:-"> Task :(compileJava|compileTestJava) NO-SOURCE"}
# single alternation regex (grep -E)
INFRA_FAILURE_PATTERNS=${INFRA_FAILURE_PATTERNS:-'^(Could not import runpy module|Traceback \(most recent call last\):|Fatal [[:alpha:]].*error:|ModuleNotFoundError: No module named )'}

readonly PSEUDO_FS=( /proc /dev /sys /run )

while [[ $# -gt 0 ]]; do
  case "$1" in
    --script)         BUILD_SCRIPT="$2"; shift 2;;
    --target)         TARGET="$2"; shift 2;;
    --env)            EXPLICIT_ENV+=("$2"); shift 2;;
    --assignment-dir) ASSIGN_DIR="$2"; shift 2;;
    --test-dir)       TEST_DIR="$2"; shift 2;;
    --verbose)        LOG_ENABLED=1; shift;;
    --lang)           LANG="$2"; shift 2;;
    *)                echo "Unknown argument: $1" >&2; exit 1;;
  esac
done

# --target used to default to "/", so a caller that forgot it scanned the whole host
# and bound its top-level directories writable while deciding whether they had to be.
# Naming it is now the caller's job. realpath -e canonicalises it and refuses a path that
# does not exist; what keeps the run inside it is init_config descending into its
# children rather than matching its name as a prefix.
[[ -n "$TARGET" ]] || err "--target is required; name the tree to prune, for example --target /"
TARGET="$(realpath -e -- "$TARGET" 2>/dev/null)" || err "--target is not a path that exists"
[[ -d "$TARGET" ]] || err "--target is not a directory: $TARGET"

PERSISTENT_BUILD_HOME="${PERSISTENT_BUILD_HOME:-}"
BUILD_OPTS="${BUILD_OPTS:-}"
IFS=',' read -r -a EXTRA_RO <<<"${BWRAP_EXTRA_RO:-}"
IFS=',' read -r -a EXTRA_RW <<<"${BWRAP_EXTRA_RW:-}"
for p in "${EXTRA_RO[@]}"; do [[ -z "$p" ]] || [[ -e $p ]] || err "BWRAP_EXTRA_RO path does not exist: $p"; done
for p in "${EXTRA_RW[@]}"; do [[ -z "$p" ]] || [[ -e $p ]] || err "BWRAP_EXTRA_RW path does not exist: $p"; done

# ── host vs sandbox paths ────────────────────────────────────────────────────
IN_SB_ROOT="/var/tmp/testing-dir"
HOST_WORKDIR="${HOST_WORKDIR:-}"   # may be injected by wrapper

# Auto-fallback: if BUILD_SCRIPT is an in-sandbox path and HOST_WORKDIR is empty,
# assume we’re running from the host copy of the exercise and PWD mirrors IN_SB_ROOT.
if [[ "$BUILD_SCRIPT" == "$IN_SB_ROOT/"* && -z "$HOST_WORKDIR" ]]; then
  rel="${BUILD_SCRIPT#${IN_SB_ROOT}/}"        # e.g. "build_script.sh" or "subdir/file"
  if [[ -e "$PWD/$rel" ]]; then
    HOST_WORKDIR="$PWD"
  fi
fi

# Decide sandbox workdir + script path
if [[ -e "$BUILD_SCRIPT" ]]; then
  # host path supplied (less common)
  #
  # HOST_WORKDIR is required here too, even though this branch does not derive the
  # workdir from it: build_bwrap_command binds it unconditionally, so without it the
  # sandbox is built around an empty path and the run fails somewhere further on,
  # naming neither this branch nor the missing value.
  [[ -n "$HOST_WORKDIR" && -d "$HOST_WORKDIR" ]] \
    || err "BUILD_SCRIPT is a host path; set HOST_WORKDIR to the host exercise folder"
  SANDBOX_WORKDIR="$(cd "$(dirname "$BUILD_SCRIPT")" && pwd)"
  IN_SB_SCRIPT="$BUILD_SCRIPT"
else
  # in-sandbox path supplied (recommended); need the host dir to bind
  [[ -n "$HOST_WORKDIR" && -d "$HOST_WORKDIR" ]] \
    || err "BUILD_SCRIPT is an in-sandbox path; set HOST_WORKDIR to the host exercise folder"
  SANDBOX_WORKDIR="$IN_SB_ROOT"
  IN_SB_SCRIPT="$BUILD_SCRIPT"
fi

log "BUILD_SCRIPT=${BUILD_SCRIPT}"
log "HOST_WORKDIR=${HOST_WORKDIR:-<unset>}"
log "SANDBOX_WORKDIR=${SANDBOX_WORKDIR}"
log "IN_SB_SCRIPT=${IN_SB_SCRIPT}"

# ── state ────────────────────────────────────────────────────────────────────
unset -v PROTECTED_R CONFIG 2>/dev/null || true
declare -A PROTECTED_R
declare -A CONFIG
PROTECTED_R["$SANDBOX_WORKDIR"]=1   # never hide the mountpoint

BWRAP_COMMAND_COUNT=0
BWRAP_COMMAND=()

# Where the per-invocation logs go. Configurable so that a test can keep its own inside
# its fixture: two runs writing build-1.log into a shared /tmp would otherwise read and
# delete each other's evidence.
PRUNE_LOG_DIR="${PRUNE_LOG_DIR:-/tmp}"
mkdir -p "$PRUNE_LOG_DIR"

# What survives --clearenv. A build needs a PATH and a home to run at all; anything
# beyond that a caller names with --env, so nothing arrives merely because it happened
# to be set in the shell that started the prune.
: "${PRUNE_ENV_PASSTHROUGH:=PATH HOME LANG LC_ALL TERM}"

# ── base & tail options ──────────────────────────────────────────────────────
# --tmpfs /tmp used to be followed by --bind /tmp /tmp, which mounted the host's /tmp
# straight over it. The sandbox could then read and write everything any other process
# on the machine had left there, and the tmpfs bought nothing at all.
BASE_OPTIONS=(
  --tmpfs /
  --tmpfs /tmp
  --clearenv
)

for d in /bin /usr/bin /lib /lib64 /usr/lib /lib/x86_64-linux-gnu; do
  [[ -e "$d" ]] && BASE_OPTIONS+=( --ro-bind "$d" "$d" )
done
[[ -d /etc ]] && BASE_OPTIONS+=( --ro-bind /etc /etc )

# --new-session detaches the sandbox from the controlling terminal. Without it, and
# without a seccomp filter, a process inside can push characters back into that terminal
# with TIOCSTI and have them run outside. Bubblewrap's own guidance asks for one or the
# other, and this sandbox has no seccomp filter.
#
# --unshare-user is deliberately absent, although the committed core/config/TailPhobos.cfg
# names it. What is generated here has to be the sandbox the measurement was actually made
# in; adding an option the prune never ran under would produce a policy nobody has tested.
# Adding it is a change to the sandbox, and belongs with whoever owns that decision.
TAIL_OPTIONS=( --proc /proc --dev /dev --share-net --new-session --unshare-pid --unshare-uts --unshare-ipc --chdir "$SANDBOX_WORKDIR" )

# ── init candidate config ────────────────────────────────────────────────────
# The candidates: the children of the target, and nothing else.
#
# This used to glob "$TARGET"* , which is a prefix match rather than a descent. A target
# of /srv/work therefore also caught /srv/work-secrets, a sibling the caller never named,
# and pulled it into the configuration as writable in every invocation. prune_tree only
# ever descends into the target, so such a sibling was never revisited either: it entered
# writable and stayed writable, all the way into the generated policy.
#
# The %/ is for a target of "/", where "$TARGET"/* would glob "//*" and leave every path
# with a doubled leading slash, which would then not match the pseudo-filesystem list.
init_config() {
  shopt -s dotglob nullglob
  for item in "${TARGET%/}"/*; do
    [[ -d $item ]] || continue
    is_in_list "$item" "${PSEUDO_FS[@]}" && continue
    CONFIG["$item"]="r"
  done
  shopt -u dotglob nullglob
}

# ── build bwrap invocation ───────────────────────────────────────────────────

# The invocation, as an argument vector, in BWRAP_COMMAND.
#
# It used to be rendered into one string and run through `bash -c`, so every path and
# every value went through a second round of shell parsing on the way in: a directory
# whose name held a quote, a dollar or a semicolon was a command waiting for its turn.
# An array reaches the kernel as it stands, and the build script is now passed as an
# argument rather than as text for a shell to interpret.
#
# The environment is cleared and rebuilt rather than inherited, so nothing the caller
# happens to be holding, a token or a path to a runner control file, is visible to code
# the sandbox is meant to contain. PRUNE_ENV_PASSTHROUGH names what survives; --env adds
# to it.
build_bwrap_command() {
  local options=("${BASE_OPTIONS[@]}")
  if [[ "$TARGET" != "/" ]]; then
    options+=( --ro-bind "$TARGET" "$TARGET" )
  fi

  local list=() path depth weight state
  for path in "${!CONFIG[@]}"; do
    [[ -z "$path" ]] && continue
    depth=$(grep -o "/" <<<"$path" | wc -l || true)
    state="${CONFIG[$path]}"
    case "$state" in n) weight=0;; r) weight=1;; w) weight=2;; esac
    list+=("$depth:$weight:$path")
  done

  local sorted_paths=()
  ((${#list[@]})) && readarray -t sorted_paths < <(
    printf '%s\n' "${list[@]}" | sort -t: -k1,1n -k2,2n | cut -d: -f3-
  )

  for path in "${sorted_paths[@]}"; do
    [[ -z "$path" ]] && continue
    state="${CONFIG[$path]:-}" ; [[ -z "$state" ]] && continue
    case "$state" in
      n) options+=( --tmpfs "$path" ) ;;
      r) options+=( --ro-bind "$path" "$path" ) ;;
      w) options+=( --bind    "$path" "$path" ) ;;
    esac
  done

  for p in "${EXTRA_RO[@]}"; do [[ -z "$p" ]] || options+=( --ro-bind "$p" "$p" ); done
  for p in "${EXTRA_RW[@]}"; do [[ -z "$p" ]] || options+=( --bind    "$p" "$p" ); done
  # Ensure sandbox path exists, then bind the host exercise *after* parent mounts
  options+=( --dir /var --dir /var/tmp --dir "$SANDBOX_WORKDIR" )
  options+=( --bind "$HOST_WORKDIR" "$SANDBOX_WORKDIR" )
  options+=("${TAIL_OPTIONS[@]}")

  local name value
  for name in ${PRUNE_ENV_PASSTHROUGH}; do
    [[ -n "${!name:-}" ]] && options+=( --setenv "$name" "${!name}" )
  done
  [[ -n "$PERSISTENT_BUILD_HOME" ]] && options+=( --setenv BUILD_HOME "$PERSISTENT_BUILD_HOME" )
  [[ -n "$BUILD_OPTS" ]] && options+=( --setenv BUILD_OPTS "$BUILD_OPTS" )
  for value in ${EXPLICIT_ENV[@]+"${EXPLICIT_ENV[@]}"}; do
    options+=( --setenv "${value%%=*}" "${value#*=}" )
  done

  BWRAP_COMMAND=( bwrap "${options[@]}" /bin/bash "$IN_SB_SCRIPT" )
}

# ── run one attempt ──────────────────────────────────────────────────────────
test_build_script() {
  local tmpfile exit_code status
  build_bwrap_command
  ((BWRAP_COMMAND_COUNT++))
  log "Testing command number: $BWRAP_COMMAND_COUNT"

  tmpfile="${PRUNE_LOG_DIR}/build-${BWRAP_COMMAND_COUNT}.log"
  {
    echo "=== Run #${BWRAP_COMMAND_COUNT} Command ==="
    printf '%q ' "${BWRAP_COMMAND[@]}"
    echo
    echo
  } >"$tmpfile"

  set +e
  "${BWRAP_COMMAND[@]}" >>"$tmpfile" 2>&1
  exit_code=$?
  set -e

  # non-zero but ignorable → success
  if (( exit_code != 0 )) && [[ -n ${IGNORABLE_FAILURE_PATTERNS:-} ]] \
     && grep -Eq "${IGNORABLE_FAILURE_PATTERNS}" "$tmpfile"; then
    exit_code=0
  fi
  # zero but infra-fatal lines present → failure
  if (( exit_code == 0 )) && [[ -n ${INFRA_FAILURE_PATTERNS:-} ]] \
     && grep -Eq "${INFRA_FAILURE_PATTERNS}" "$tmpfile"; then
    exit_code=1
  fi
  # zero but “unignorable success” → failure
  if (( exit_code == 0 )) && [[ -n ${UNIGNORABLE_SUCCESS_PATTERNS:-} ]] \
     && grep -Eq "${UNIGNORABLE_SUCCESS_PATTERNS}" "$tmpfile"; then
    exit_code=1
  fi

  [[ $exit_code -eq 0 ]] && status="success" || status="fail"
  mv "$tmpfile" "${PRUNE_LOG_DIR}/build-${BWRAP_COMMAND_COUNT}-${status}.log"
  log "Logs for run #${BWRAP_COMMAND_COUNT}: ${PRUNE_LOG_DIR}/build-${BWRAP_COMMAND_COUNT}-${status}.log"
  return $exit_code
}

# ── pruning (hide → ro → rw) ─────────────────────────────────────────────────
prune_tree() {
  local parent="$1"
  log "Pruning subdirectories of $parent"
  for child in "${parent%/}"/*; do
    [[ -d "$child" ]] || continue
    is_in_list "$child" "${PSEUDO_FS[@]}" && continue
    [[ -n "${PROTECTED_R[$child]:-}" ]] && continue

    log "Testing candidate: $child"
    CONFIG["$child"]="n"
    if test_build_script; then
      log "$child => not required (n)"
    else
      CONFIG["$child"]="r"
      if test_build_script; then
        log "$child => read-only (r)"
      else
        CONFIG["$child"]="w"
        if test_build_script; then
          log "$child => must be writable (w)"
        else
          log "$child => fails even with w, keep as w"
          CONFIG["$child"]="w"
        fi
      fi
    fi
    if [[ -v CONFIG["$child"] ]] && [[ "${CONFIG[$child]}" != "n" ]]; then
      prune_tree "$child"
    fi
  done
}

# ── compaction (best-effort) ─────────────────────────────────────────────────
collapse_readonly_parents() {
  local parent child all_r any_child
  local _oldnullglob _olddotglob
  shopt -q nullglob; _oldnullglob=$?
  shopt -q dotglob;  _olddotglob=$?
  shopt -s nullglob dotglob

  local -a parents=(); local k
  for k in "${!CONFIG[@]}"; do parents+=("$k"); done

  for parent in "${parents[@]}"; do
    [[ "${CONFIG[$parent]:-}" = r ]] || continue
    all_r=true; any_child=false
    for child in "$parent"/*; do
      [[ -d "$child" ]] || continue
      if [[ -v CONFIG["$child"] ]]; then
        any_child=true
        [[ "${CONFIG[$child]:-}" = r ]] || { all_r=false; break; }
      fi
    done
    if $any_child && $all_r; then
      for child in "$parent"/*; do
        [[ -d "$child" ]] || continue
        [[ -v CONFIG["$child"] ]] && unset 'CONFIG[$child]'
      done
    fi
  done

  (( _oldnullglob )) && shopt -u nullglob
  (( _olddotglob  )) && shopt -u dotglob
}

demote_writable_parents() {
  local -a keys=(); local k
  for k in "${!CONFIG[@]}"; do keys+=("$k"); done
  ((${#keys[@]})) && mapfile -t keys < <(
    printf '%s\n' "${keys[@]}" | awk -F/ '{print (NF-1) "\t" $0}' | sort -rn | cut -f2-
  )

  local parent maybe any_w
  for parent in "${keys[@]}"; do
    [[ "${CONFIG[$parent]:-}" == "w" ]] || continue
    any_w=false
    for maybe in "${!CONFIG[@]}"; do
      [[ "$maybe" == "$parent"/* ]] || continue
      [[ "${CONFIG[$maybe]:-}" == "w" ]] && { any_w=true; break; }
    done
    $any_w || CONFIG["$parent"]="r"
  done
}

# ── write result ─────────────────────────────────────────────────────────────
save_configuration() {
  local outfile="final_bindings.txt"
  echo "Saving final binding configuration to $outfile" > "$outfile"
  for key in "${!CONFIG[@]}"; do
    echo "$key -> ${CONFIG[$key]}" >> "$outfile"
  done
  echo "Total Command Attempts: $BWRAP_COMMAND_COUNT" >> "$outfile"
  echo "Base options: ${BASE_OPTIONS[*]}" >> "$outfile"
  echo "Tail options: ${TAIL_OPTIONS[*]}" >> "$outfile"
  log "Total Command Attempts: $BWRAP_COMMAND_COUNT"
  log "Base options: ${BASE_OPTIONS[*]}"
  log "Tail options: ${TAIL_OPTIONS[*]}"
}

# ── main ─────────────────────────────────────────────────────────────────────
log "Initializing configuration for target: $TARGET"
init_config
for key in "${!CONFIG[@]}"; do CONFIG["$key"]="w"; done

log "Testing with full writable configuration..."
if ! test_build_script; then
  log "Build script failed even with full writable configuration. Aborting."
  exit 1
fi

log "Running pruning for exercises of ${LANG:-<unknown>}..."
prune_tree "$TARGET"

# never fail a successful prune during compaction
set +e
demote_writable_parents || true
collapse_readonly_parents || true
set -e

[[ -n "$ASSIGN_DIR" ]] && { log "Force RO on assignment dir: $ASSIGN_DIR"; CONFIG["$ASSIGN_DIR"]=r; }
[[ -n "$TEST_DIR"   ]] && { log "Force RO on test dir: $TEST_DIR";   CONFIG["$TEST_DIR"]=r; }
for p in "${EXTRA_RO[@]}"; do [[ -z "$p" ]] || CONFIG["$p"]="r"; done
for p in "${EXTRA_RW[@]}"; do [[ -z "$p" ]] || CONFIG["$p"]="w"; done

save_configuration || true
exit 0
