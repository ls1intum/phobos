#!/bin/bash
# The generic reference exercise for the layer pruner: a word-frequency script under assignment/ and a
# tester under test/ whose twelve cases use each tool of the shell base the generic run-phase image ships
# (bash, coreutils, findutils, grep, sed, gawk, diffutils, make).
#
# Like the other references it ends with status 0 whatever the tests found, so the result is the JUnit
# report test-reports/results.xml (prune.json names it) and not the exit status. The pruner requires this
# file to be executable and starts it as /bin/bash build_script.sh.
set -u
mkdir -p test-reports
make -C test test || true
