#!/bin/bash
# The Python reference exercise for the layer pruner, in the shape of Artemis's Python template
# (ls1intum/Artemis, src/main/resources/templates/python and templates/phases/python/default.yaml,
# commit a716c880cd5ea017d913afddef3533424b112e3c): the solution under assignment/, unittest test
# cases under test/behavior, and the template's two build phases verbatim, compileall and then pytest
# writing the JUnit report the pruner reads (prune.json names it). Nothing is installed or fetched:
# pytest comes with the run-phase image, and the run needs no network.
set -u
python3 -m compileall . -q || exit 1
pytest --junitxml=test-reports/results.xml
