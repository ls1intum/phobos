#!/bin/bash
# The Python reference exercise for the layer pruner: the files of Artemis's Python template
# (ls1intum/Artemis, src/main/resources/templates/python, commit b142d99f4106f4e7656ee4aff41bc68851aef192),
# laid out as Artemis lays out a build: the solution under assignment/, the test files beside it in
# behavior/ and structural/, and the template's two build phases of phases/python/default.yaml verbatim,
# compileall and then pytest writing the JUnit report the pruner reads (prune.json names it).
#
# Two things differ from the template, and nothing else: ${studentParentWorkingDirectoryName} is
# assignment, and structural/structural_helpers.py calls inspect.getfullargspec, because getargspec,
# which the template calls, no longer exists in the Python the run-phase image ships.
#
# Nothing is installed or fetched: pytest comes with the run-phase image, and the run needs no network.
set -u
python3 -m compileall . -q || exit 1
pytest --junitxml=test-reports/results.xml
