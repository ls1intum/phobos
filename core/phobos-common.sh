#!/usr/bin/env bash
# shellcheck shell=bash
# The shared library every layer and every suite sources, by this name. It defines nothing
# itself: it sets the shell options the helpers assume, reads the constants, and then reads
# the eight files below, one concern each. Splitting it changed no caller for that reason,
# and it has no include guard on purpose, because sourcing it has to keep resetting
# PHB_DEBUG_ENABLED so that the environment can never switch debugging on.
set -euo pipefail
# shellcheck source=phobos-constants.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/phobos-constants.sh"

# The components below. They are sourced here and nowhere else: a caller sources this file,
# and the split is how one concern is read at a time, not a new set of entry points. The
# order is the order they depend on each other in, although only function definitions cross
# the boundaries, so nothing is read at load time from a file that has not been read yet.
# shellcheck source=phobos-log.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/phobos-log.sh"
# shellcheck source=phobos-paths.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/phobos-paths.sh"
# shellcheck source=phobos-time.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/phobos-time.sh"
# shellcheck source=phobos-spec-dir.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/phobos-spec-dir.sh"
# shellcheck source=phobos-policy-parse.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/phobos-policy-parse.sh"
# shellcheck source=phobos-rights.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/phobos-rights.sh"
# shellcheck source=phobos-network-args.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/phobos-network-args.sh"
# shellcheck source=phobos-netblocker-check.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/phobos-netblocker-check.sh"
