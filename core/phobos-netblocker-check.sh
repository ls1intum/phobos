#!/usr/bin/env bash
# shellcheck shell=bash
# Refusing a preload library that would not filter anything.
#
# A component of phobos-common.sh, which sources this file after phobos-constants.sh
# and is what every caller sources. It sets no shell option and sources nothing, so
# that sourcing the aggregate twice keeps doing exactly what it did before the split.
# Every variable here is read by the scripts that source the aggregate, never in
# this file, so SC2034 would fire on all of them by design.
# shellcheck disable=SC2034

# --------------------------------------------------------------------------
# Refusing a preload library that would not filter anything.
#
# The loader skips a preload library it cannot use and prints only a warning, and
# the command then runs with the preload half of the network filtering missing. The
# network layer asks these functions before it hands over, so that such a run ends
# instead.
# --------------------------------------------------------------------------

# The functions the network layer relies on the preload library defining.
PHB_NETBLOCKER_HOOKS="bind connect getaddrinfo sendmmsg sendmsg sendto"

# Prints the functions a shared object defines with default visibility, one per
# line. Assumes readelf from binutils; prints nothing for a file it cannot read.
defined_library_functions() {
  readelf --dyn-syms --wide "$1" 2>/dev/null \
    | awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" { print $8 }' \
    || true
}

# Runs /bin/true with the named library preloaded and nothing else of the caller's
# environment, printing everything it wrote. Further NAME=VALUE arguments join the
# clean environment. Assumes /usr/bin/env.
#
# env -i alone is not enough: the loader reads LD_* variables while it starts env
# itself, before env has cleared anything, so the subshell removes them first.
run_with_only_preload() {
  local library="$1"
  shift
  (
    unset GLIBC_TUNABLES
    while IFS= read -r name; do
      if [[ "$name" == LD_* ]]; then unset "$name"; fi
    done < <(compgen -e)
    exec /usr/bin/env -i LC_ALL=C LD_BIND_NOW=1 LD_PRELOAD="$library" "$@" /bin/true
  ) 2>&1
}

# Prints why the library cannot act as the network filter, or nothing when it can.
# Assumes the path is already canonical. A space or a colon separates entries in
# LD_PRELOAD, so a path holding one cannot be named there unambiguously.
netblocker_unusable_reason() {
  local library="$1"
  local functions
  local hook
  local output
  if [[ "$library" == *[[:space:]:]* ]]; then
    printf 'holds a space or a colon, which LD_PRELOAD cannot name'
    return 0
  fi
  if [[ ! -f "$library" ]]; then
    printf 'does not exist'
    return 0
  fi
  if ! command -v readelf >/dev/null 2>&1; then
    printf 'cannot be inspected, because readelf is not installed'
    return 0
  fi
  functions="$(defined_library_functions "$library")"
  for hook in ${PHB_NETBLOCKER_HOOKS}; do
    if ! grep -qx -- "$hook" <<<"$functions"; then
      printf 'does not define %s' "$hook"
      return 0
    fi
  done
  if ! output="$(run_with_only_preload "$library")" || [[ -n "$output" ]]; then
    printf 'does not load cleanly: %s' "${output:-a non-zero exit status}"
    return 0
  fi
  if ! output="$(run_with_only_preload "$library" LD_TRACE_LOADED_OBJECTS=1)" \
     || ! awk -v wanted="$library" '$1 == wanted { found = 1 } END { exit !found }' <<<"$output"; then
    printf 'is not among the objects the loader maps'
    return 0
  fi
}

# Ends the run with PHB-ERUNTIME unless the library can act as the network filter.
# Assumes the path is already canonical.
refuse_unusable_netblocker() {
  local library="$1"
  local reason
  reason="$(netblocker_unusable_reason "$library")"
  [[ -z "$reason" ]] && return 0
  report "Network layer unusable: '${library}' ${reason}, so the command would run unfiltered. (PHB-ERUNTIME)"
  exit "${PHB_ERUNTIME}"
}

# Appends the rules that let the preload library and its rules file be read inside
# the sandbox, and refuses a policy under which either could be changed from inside
# it. Assumes both paths exist and that the write file holds the policy's write
# paths, one per line; the other sections grant no right that changes a file.
#
# Landlock adds the rights of every rule along a path and cannot take one away, so a
# read rule on a file beneath a write path would still leave it writable, and a
# submission could rewrite its network policy or replace the library that enforces
# it before starting another process. Symbolic links are resolved on both sides,
# because Landlock anchors a rule on the inode it opens. The bind rules are added with an
# if rather than a "&&", so that an empty bind_rules leaves the function returning zero
# rather than the 1 of a false test, which under the caller's set -e would end the run.
append_netblocker_rules() {
  local -n netblocker_ref="$1"
  local write_file="$2"
  local library="$3"
  local rules="$4"
  local bind_rules="$5"
  local artefact
  local resolved
  local write_path
  local resolved_write
  for artefact in "$library" "$rules" "$bind_rules"; do
    [[ -n "$artefact" ]] || continue
    resolved="$(printf '%s\n' "$artefact" | resolve_symlinks)"
    while IFS= read -r write_path || [[ -n "$write_path" ]]; do
      [[ -z "$write_path" ]] && continue
      resolved_write="$(printf '%s\n' "$write_path" | resolve_symlinks)"
      if [[ "$resolved" == "$resolved_write" || "$resolved" == "${resolved_write%/}/"* ]]; then
        report "Policy unenforceable: '${artefact}' lies beneath the write path '${write_path}', so the sandbox could change the network policy or the library that enforces it. (PHB-EPOLICY)"
        exit "${PHB_EPOLICY}"
      fi
    done < <(cat "$write_file" 2>/dev/null)
  done
  netblocker_ref+=( --rights=rx "$library" --rights=r "$rules" )
  if [[ -n "$bind_rules" ]]; then
    netblocker_ref+=( --rights=r "$bind_rules" )
  fi
}
