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

[[ $# -eq 2 ]] || { printf 'usage: record-capability.sh <name> <probe mode>\n' >&2; exit 2; }
name="$1"
mode="$2"

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
bash "${HERE}/../../tests/runner-capability-probe.sh" "${mode}"
status="$?"

case "${status}" in
    0) verdict="available" ;;
    1) verdict="unavailable" ;;
    *) verdict="indeterminate" ;;
esac

printf '%s: %s\n' "${name}" "${verdict}"
[[ -n "${GITHUB_OUTPUT:-}" ]] && printf 'verdict=%s\n' "${verdict}" >>"${GITHUB_OUTPUT}"
exit 0
