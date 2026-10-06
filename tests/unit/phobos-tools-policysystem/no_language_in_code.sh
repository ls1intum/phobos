#!/usr/bin/env bash
# Phobos knows no programming language: everything that depends on one lives in a programming
# language configuration under core/config/, and the code under core/ only reads it. This suite
# holds the code to that by searching it for the names a Java configuration of Ares 2 uses, and
# first shows that the same search does find them where they belong, so that a search that can
# match nothing does not pass for a clean result.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="${HERE}/../../../core"

# The names that only a programming language configuration may hold: Ares 2's configuration names
# and the placeholders of its Java configurations.
LANGUAGE_NAMES='JAVA_USING|java\.home|user\.home|java\.io\.tmpdir'

found="$(grep -rn -E "$LANGUAGE_NAMES" "${CORE}/config/language-configurations" | wc -l)"
if (( found > 0 )); then
  ok "the search finds the language names in the programming language configurations (${found} lines)"
else
  bad "the search finds the language names in the programming language configurations" "at least one line" "none"
fi

found="$(grep -rn -E "$LANGUAGE_NAMES" "${CORE}" --exclude-dir=config)"
check "no script, helper or C source under core/ outside core/config/ names a programming language configuration or its placeholders" "" "$found"

finish
