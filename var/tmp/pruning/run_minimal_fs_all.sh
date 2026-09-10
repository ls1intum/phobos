#!/usr/bin/env bash
# run_minimal_fs_all.sh – prune every exercise for a single language
set -euo pipefail
trap 'echo "[ERR ] aborted at line $LINENO (status $?)" >&2' ERR

HELPER_DIR="${HELPER_DIR:-/var/tmp/helpers}"
EMIT_HELPER="$HELPER_DIR/emit_artifacts.py"
PHOBOS_KEEP_LOG="${PHOBOS_KEEP_LOG:-0}"

LOG_ENABLED=0
CACHE_DIR=""
lang=""

usage() {
  cat >&2 <<EOF
Usage: $0 [--verbose] [--cache-dir PATH] <lang>
  --verbose        enable debug logging
  --cache-dir PATH bind PATH read-write inside Bubblewrap (tool-agnostic cache)
EOF
  exit 1
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verbose) LOG_ENABLED=1; shift;;
    --cache-dir) [[ $# -ge 2 ]] || { echo "Missing path after --cache-dir" >&2; usage; }
                 CACHE_DIR=$2; shift 2;;
    -h|--help) usage;;
    --*) echo "Unknown flag: $1" >&2; usage;;
    *)  if [[ -z ${lang:-} ]]; then lang=$1; else echo "Unexpected arg: $1" >&2; usage; fi; shift;;
  esac
done
[[ -n ${lang:-} ]] || usage

log()   { (( LOG_ENABLED )) && echo "[LOG ] $*"; return 0; }
info()  { echo "[INFO] $*"; }
error() { echo "[FAIL] $*" >&2; exit 1; }

EX_ROOT="${TESTING_DIR:-/var/tmp/testing-dir}/$lang"
PRUNE_SCRIPT="${PRUNE_SCRIPT:-/var/tmp/pruning/detect_minimal_fs.sh}"
OUTPUT_DIR="${OUTPUT_DIR:-/var/tmp/path_sets}"

[[ -d "$EX_ROOT"      ]] || error "Language folder not found: $EX_ROOT"
[[ -x "$PRUNE_SCRIPT" ]] || error "Prune script not exec: $PRUNE_SCRIPT"
mkdir -p "$OUTPUT_DIR" "$HELPER_DIR" 2>/dev/null || true

if [[ -n "$CACHE_DIR" ]]; then
  mkdir -p "$CACHE_DIR"
  export BWRAP_EXTRA_RW="$CACHE_DIR"
  log "Cache directory bound RW: $CACHE_DIR"
fi

shopt -s nullglob

# This language's artefacts from the previous run, removed before it produces its
# own. The orchestrator asks afterwards whether each language produced a result, and
# a file left over from last week answers yes on behalf of a language that produced
# nothing today. It has to happen here rather than in the orchestrator: the compose
# pipeline runs the orchestrator with --skip-prune, so anything it cleared would be
# cleared after these artefacts had already been written.
stale_artefacts=("$OUTPUT_DIR/${lang}"_*)
if (( ${#stale_artefacts[@]} )); then
  log "Removing ${#stale_artefacts[@]} artefact(s) left by an earlier run of $lang"
  rm -f -- "${stale_artefacts[@]}"
fi

exercises=("$EX_ROOT"/*)
[[ ${#exercises[@]} -gt 0 ]] || error "No exercises found for $lang"

for ex_dir in "${exercises[@]}"; do
  if   [[ -x "$ex_dir/build_script"    ]]; then build_script_rel="build_script"
  elif [[ -x "$ex_dir/build_script.sh" ]]; then build_script_rel="build_script.sh"
  else log "Skipping $(basename "$ex_dir") – build_script not found or not exec"; continue
  fi
  [[ -d "$ex_dir/assignment" ]] || { log "Skipping $(basename "$ex_dir") – missing assignment"; continue; }

  ex_name=$(basename "$ex_dir")
  info "=== Processing $ex_name ($lang) ==="

  # per-exercise scratch (host), then copy exercise there
  # Under TMPDIR where one is set, rather than always /tmp. A caller that points TMPDIR
  # somewhere of its own then really gets its scratch there, which is what lets a test
  # keep the copied exercise inside its own fixture instead of in a shared directory.
  workroot=$(mktemp -d "${TMPDIR:-/tmp}/prune_${lang}_${ex_name}_XXXX")
  host_workdir="$workroot/exercise"
  mkdir -p "$host_workdir"
  cp -a "$ex_dir"/. "$host_workdir"/
  chmod -R u+w "$host_workdir"

  # production-like sandbox paths
  IN_SB_ROOT="/var/tmp/testing-dir"
  IN_SB_SCRIPT="$IN_SB_ROOT/$build_script_rel"
  IN_SB_ASSIGN="$IN_SB_ROOT/assignment"
  IN_SB_TESTS="$IN_SB_ROOT"

  pushd "$host_workdir" >/dev/null
  # --target is no longer optional, and defaults here to the whole filesystem because
  # that is what a production prune inspects. A test points PRUNE_TARGET at a fixture
  # tree instead, so it never asks what the machine it runs on happens to need.
  PRUNE_ARGS=( --script "$IN_SB_SCRIPT" --lang "$lang" --target "${PRUNE_TARGET:-/}"
               --assignment-dir "$IN_SB_ASSIGN" --test-dir "$IN_SB_TESTS" )
  (( LOG_ENABLED )) && PRUNE_ARGS=( --verbose "${PRUNE_ARGS[@]}" )

  # Explicitly export HOST_WORKDIR so the pruner can bind it into /var/tmp/testing-dir
  export HOST_WORKDIR="$host_workdir"
  "$PRUNE_SCRIPT" "${PRUNE_ARGS[@]}"
  popd >/dev/null

  bindings_src="$host_workdir/final_bindings.txt"
  [[ -f "$bindings_src" ]] || error "final_bindings.txt missing for $ex_name"

  if [[ -x "$EMIT_HELPER" ]]; then
    log "Emitting artifacts for $ex_name -> $OUTPUT_DIR"
    if python3 "$EMIT_HELPER" \
         --lang "$lang" \
         --exercise "$ex_name" \
         --config-file "$bindings_src" \
         --workdir "$host_workdir" \
         --runtime-root "/var/tmp/testing-dir" \
         --out-dir "$OUTPUT_DIR"; then
      (( PHOBOS_KEEP_LOG )) && mv "$bindings_src" "$OUTPUT_DIR/final_bindings_${lang}_${ex_name}.txt" || rm -f "$bindings_src"
    else
      mv "$bindings_src" "$OUTPUT_DIR/final_bindings_${lang}_${ex_name}.txt"
      error "emit_artifacts.py failed for $ex_name; raw log kept in $OUTPUT_DIR"
    fi
  else
    log "emit_artifacts helper not found ($EMIT_HELPER); copying raw log."
    mv "$bindings_src" "$OUTPUT_DIR/final_bindings_${lang}_${ex_name}.txt"
  fi

  rm -rf "$workroot"
done

info "All $lang exercises pruned – artifacts in $OUTPUT_DIR"
