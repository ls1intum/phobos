#!/bin/bash
# The files of the reference are those of Artemis's Java template (ls1intum/Artemis, src/main/resources/templates,
# commit b142d99f4106f4e7656ee4aff41bc68851aef192), laid out as Artemis lays out a build: the solution
# (java/solution and java/maven_maven/solution) under assignment/src/de/phobos/reference, and the test files
# (java/test/testFiles) beside each other in test/de/phobos/reference, where Artemis copies them without their
# folders, so that the Ares structural tests find test.json as a resource of their package. ${packageName} is
# de.phobos.reference. SecurityPolicy.yaml is the policy of java/test/maven/projectTemplate.
# What is Phobos's own, and the one deviation from the template: pom.xml and .mvn/jvm.config, which pin every version the build
# resolves, because a prune must not fetch a version that nobody pinned (AGENTS.md).
#
# The build of the Maven reference exercise: Artemis's own `mvn clean test`, offline, in batch mode, and
# failing when the project has no tests, because Surefire reports a project without tests as a success.
# It runs in /var/tmp/testing-dir, where grading runs it, and does nothing else.
set -euo pipefail
cd /var/tmp/testing-dir
exec mvn --offline --batch-mode -DfailIfNoTests=true clean test
