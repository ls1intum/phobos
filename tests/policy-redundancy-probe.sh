#!/usr/bin/env bash
# Not a suite: it reports which entries of a policy grant Landlock nothing an ancestor entry
# does not already grant it, and it never fails a build for finding one.
#
# Landlock unions the rights of every rule along a path, so an entry beneath a rule that
# already grants at least as much adds nothing to the ruleset. Such an entry is worth seeing
# when judging a freshly pruned policy, because a policy that reads as a careful enumeration
# can be a handful of wide grants with decoration beneath them.
#
# It is a report and not a gate, and the distinction matters: these entries are not dead.
# AGENTS.md records what they do, and tests/filesystem_policy.sh pins it: a base entry an
# ancestor already covers is what lets an exercise configuration name that same path with
# fewer rights, so deleting one changes which configurations Phobos accepts. Read the output,
# do not act on it mechanically.
#
#   tests/policy-redundancy-probe.sh <policy.cfg>...
#
# Paths are resolved through their symbolic links first, as the filesystem layer resolves
# them, because Landlock anchors a rule on the inode it opens: /bin and /usr/bin are one tree
# on a merged-usr system although they are two lines in the policy. That makes the answer
# specific to the filesystem it runs on, so run it where the policy is applied, inside the
# run-phase image, rather than on a machine whose layout differs.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="${HERE}/../core"
# shellcheck source=../core/phobos-tools-common/phobos-common.sh
source "${CORE}/phobos-tools-common/phobos-common.sh"

# The exit status this probe ends with when it was called the wrong way.
readonly PROBE_EXIT_USAGE=2

# The sections whose entries this probe compares, and the rights letter each grants. The
# order is the one phobos-common.sh uses, so a set of letters prints the way the manual reads.
readonly PROBE_SECTIONS="read:r execute:x write:w create:m delete:d"

# Prints how to call the probe and ends with PROBE_EXIT_USAGE.
usage() {
  printf 'usage: policy-redundancy-probe.sh <policy.cfg>...\n' >&2
  exit "${PROBE_EXIT_USAGE}"
}

# Prints one "resolved path<TAB>rights" line per distinct path of a policy cfg, the rights
# being every section's letter that names it. Reads the sections the way parse_cfg_policy
# does, comments and blank lines dropped, and deliberately does not use collect_rights_table:
# that one creates a missing write, create or delete path, which a report must never do.
collect_policy_rights() {
  local cfg="$1"
  local section=""
  local line
  local pair
  local letter
  local -A rights=()
  local -A order=()
  local position=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^\[(.+)\]$ ]]; then
      section="${BASH_REMATCH[1]}"
      continue
    fi
    letter=""
    for pair in ${PROBE_SECTIONS}; do
      [[ "$section" == "${pair%%:*}" ]] && letter="${pair##*:}"
    done
    [[ -z "$letter" ]] && continue
    local resolved
    resolved="$(printf '%s\n' "$line" | resolve_symlinks)"
    rights["$resolved"]="${rights["$resolved"]:-}${letter}"
    if [[ -z "${order["$resolved"]:-}" ]]; then
      position=$((position + 1))
      order["$resolved"]="$position"
    fi
  done <"$cfg"
  local path
  for path in "${!rights[@]}"; do
    printf '%s\t%s\t%s\n' "${order["$path"]}" "$path" "$(rights_normalise "${rights["$path"]}")"
  done | sort -n | cut -f2-
}

# Reports every entry of one policy whose ancestors, taken together, already grant at least
# as much, and prints the count. Together, because Landlock unions the rights of every rule
# along a path: an entry can add nothing although no single ancestor covers it alone. Takes the cfg to read. Assumes realpath from GNU coreutils, which
# refuse_missing_realpath has established.
report_policy() {
  local cfg="$1"
  local table
  local covered=0
  local total=0
  table="$(collect_policy_rights "$cfg")"
  printf '%s\n' "$cfg"
  local path
  local letters
  while IFS=$'\t' read -r path letters; do
    [[ -z "$path" ]] && continue
    total=$((total + 1))
    local ancestor_path
    local ancestor_letters
    local inherited=""
    local ancestors=""
    while IFS=$'\t' read -r ancestor_path ancestor_letters; do
      [[ -z "$ancestor_path" || "$ancestor_path" == "$path" ]] && continue
      [[ "$path" == "${ancestor_path%/}/"* ]] || continue
      inherited="${inherited}${ancestor_letters}"
      ancestors="${ancestors}${ancestors:+, }${ancestor_path} [${ancestor_letters}]"
    done <<<"$table"
    [[ -n "$inherited" ]] || continue
    rights_subset "$letters" "$inherited" || continue
    printf '  %-52s [%s] is already granted by %s\n' \
      "$path" "$letters" "$ancestors"
    covered=$((covered + 1))
  done <<<"$table"
  printf '  %d of %d entries grant nothing beyond an ancestor\n\n' "$covered" "$total"
}

[[ $# -ge 1 ]] || usage
refuse_missing_realpath
for policy in "$@"; do
  [[ -f "$policy" ]] || die "not a policy file: ${policy}" "${PROBE_EXIT_USAGE}"
  report_policy "$policy"
done
