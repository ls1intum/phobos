#!/usr/bin/env bash
# Turns one capability probe's three-valued exit status into a step output.
#
# The probe answers available, unavailable or indeterminate, and a workflow
# step can only be green or red. Collapsing the three into two inside the
# workflow is what makes a broken probe look like an absent capability, so the
# translation is written once, here, and the step stays green for all three.
# The workflow's last step is where indeterminate finally turns the run red.
#
#   record-capability.sh <name> <probe mode>
set -uo pipefail

# The status this script ends with when it was called the wrong way.
readonly EXIT_USAGE=2
# The probe's statuses for a capability that is there and for one that is not; anything else
# means the probe could not tell.
readonly PROBE_AVAILABLE=0
readonly PROBE_UNAVAILABLE=1

[[ $# -eq 2 ]] || { printf 'usage: record-capability.sh <name> <probe mode>\n' >&2; exit "${EXIT_USAGE}"; }
name="$1"
mode="$2"

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
bash "${HERE}/../../tests/runner-capability-probe.sh" "${mode}"
status="$?"

case "${status}" in
    "${PROBE_AVAILABLE}") verdict="available" ;;
    "${PROBE_UNAVAILABLE}") verdict="unavailable" ;;
    *) verdict="indeterminate" ;;
esac

printf '%s: %s\n' "${name}" "${verdict}"
[[ -n "${GITHUB_OUTPUT:-}" ]] && printf 'verdict=%s\n' "${verdict}" >>"${GITHUB_OUTPUT}"
exit 0
