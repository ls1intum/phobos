#!/usr/bin/env bash
# shellcheck shell=bash
# The two canonical forms a path is compared in, and the tool both need.
#
# A component of phobos-common.sh, which sources this file after phobos-constants.sh
# and is what every caller sources. It sets no shell option and sources nothing, so
# that sourcing the aggregate twice keeps doing exactly what it did before the split.
# Drops repeated lines from standard input, keeping the first of each in its place.
uniq_keep_order() { awk '!seen[$0]++'; }
# Sorts paths on standard input by their depth, then by name, so a parent comes before its
# children.
depth_sort()      { awk '{print gsub(/\//,"/")+1 " " $0}' | sort -k1,1n -k2,2 | cut -d" " -f2-; }
# Prints each path on standard input in canonical form, without resolving symbolic links, so the
# merge compares what the policy wrote. Assumes realpath from GNU coreutils, which
# refuse_missing_realpath has established; a path it cannot canonicalise passes through as
# written.
canon_paths() {
  while IFS= read -r p; do [[ -z "$p" ]] && continue; realpath --canonicalize-missing --no-symlinks "$p" || printf '%s\n' "$p"; done
}

# Resolves each path on standard input through its symbolic links and prints it.
# Assumes realpath from GNU coreutils, which refuse_missing_realpath has
# established; a path it cannot resolve passes through as written.
#
# canon_paths deliberately passes --no-symlinks, because the merge logic compares
# what the policy wrote. This needs the opposite: Landlock anchors a rule on the
# inode it opens, so /bin and /usr/bin are one tree on a merged-usr system even
# though they are two lines in the policy.
resolve_symlinks() {
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    realpath --canonicalize-missing "$p" 2>/dev/null || printf '%s\n' "$p"
  done
}

# Ends the run unless realpath takes the options this file calls it with. The check runs the
# tool rather than looking for its name, because a realpath that refuses those options, as
# the BSD and BusyBox ones do, would otherwise pass here and then leave every path to the
# fallback below, which is the quieter sandbox this refusal exists to prevent. Both canonical
# forms this file prints depend on it: the merge compares what a policy wrote, and the hierarchy check compares the targets
# Landlock anchors a rule on. Passing a path through unchanged instead would compare
# spellings, so /bin and /usr/bin would look like two trees on a merged-usr system and a
# narrowing rule beneath a wider one would go unnoticed. That is a weaker sandbox that still
# looks like one, so the tool is required rather than worked around. Assumes it is called
# plainly, so that the refusal ends the run.
refuse_missing_realpath() {
  realpath --canonicalize-missing --no-symlinks / >/dev/null 2>&1 && return 0
  report "Runtime unusable: realpath does not take --canonicalize-missing --no-symlinks, so a policy's paths cannot be canonicalised. GNU coreutils is what provides it. (PHB-ERUNTIME)"
  exit "${PHB_ERUNTIME}"
}
