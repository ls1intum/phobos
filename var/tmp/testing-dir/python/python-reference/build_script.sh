#!/bin/bash
# The Python reference exercise for the layer pruner, in the shape of Artemis's Python template: the
# solution under assignment/, its tests under tests/, run by pytest, which writes the JUnit report the
# pruner reads (prune.json names it). Nothing is installed or fetched: pytest comes with the
# run-phase image, and the run needs no network.
set -u
python3 -m pytest -q -p no:cacheprovider --junitxml=test-reports/results.xml tests
