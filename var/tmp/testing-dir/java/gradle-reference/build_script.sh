#!/bin/bash
# The build of the Gradle reference exercise: Artemis's own `./gradlew clean test`, offline. It runs in
# /var/tmp/testing-dir, where grading runs it, and does nothing else. The settings that keep Gradle from
# forking a daemon and pin its heap are in gradle.properties and gradlew, which grading uses as they are.
set -euo pipefail
cd /var/tmp/testing-dir
exec ./gradlew --offline clean test
