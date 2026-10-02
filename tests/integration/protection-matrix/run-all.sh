#!/usr/bin/env bash
# Runs the protection matrix suites one after the other inside the run-phase image, or the ones named, and ends
# non-zero when any of them did. CI runs each suite in a step of its own; this is for running them by hand.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUITES=(filesystem network timeout resources combinations cli lifecycle)
if (( $# > 0 )); then
  SUITES=("$@")
fi
failed=()
for suite in "${SUITES[@]}"; do
  echo
  echo "################ ${suite} ################"
  bash "${PM_HERE}/${suite}.sh" || failed+=("$suite")
done
echo
if (( ${#failed[@]} > 0 )); then
  echo "Failed suites: ${failed[*]}"
  exit 1
fi
echo "All suites passed."
