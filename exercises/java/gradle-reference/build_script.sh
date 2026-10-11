#!/bin/bash
# The files of the reference are those of Artemis's Java template (ls1intum/Artemis, src/main/resources/templates,
# commit b142d99f4106f4e7656ee4aff41bc68851aef192), laid out as Artemis lays out a build: the solution
# (java/solution and java/gradle_gradle/solution) under assignment/src/de/phobos/reference, and the test files
# (java/test/testFiles) beside each other in test/de/phobos/reference, where Artemis copies them without their
# folders, so that the Ares structural tests find test.json as a resource of their package. ${packageName} is
# de.phobos.reference. SecurityPolicy.yaml is the policy of java/test/gradle/projectTemplate.
# What is Phobos's own, and the one deviation from the template: build.gradle, settings.gradle, gradle.properties, gradlew and the wrapper, which pin every version the build
# resolves, because a prune must not fetch a version that nobody pinned (AGENTS.md).
#
# The build of the Gradle reference exercise: Artemis's own `./gradlew clean test`, offline. It runs in
# /var/tmp/testing-dir, where grading runs it, and does nothing else. The settings that keep Gradle from
# forking a daemon and pin its heap are in gradle.properties and gradlew, which grading uses as they are.
set -euo pipefail
cd /var/tmp/testing-dir
exec ./gradlew --offline clean test
