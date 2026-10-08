#!/bin/bash
# The build of the Maven reference exercise: Artemis's own `mvn clean test`, offline, in batch mode, and
# failing when the project has no tests, because Surefire reports a project without tests as a success.
# It runs in /var/tmp/testing-dir, where grading runs it, and does nothing else.
set -euo pipefail
cd /var/tmp/testing-dir
exec mvn --offline --batch-mode -DfailIfNoTests=true clean test
