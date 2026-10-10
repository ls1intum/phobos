#!/bin/bash
# The Swift reference exercise for the layer pruner: the files of Artemis's Swift template (ls1intum/Artemis,
# src/main/resources/templates/swift, commit b142d99f4106f4e7656ee4aff41bc68851aef192), laid out as Artemis lays out a
# build: the solution under assignment/ and the tests beside it in test/. ${packageName} and ${packageNameFolder} are
# Reference. The phases are those of templates/phases/swift/plain.yaml, in order: setup (the tests and the test
# package file go into the directory of the solution), compile (swift build) and test (swift test, which writes the
# JUnit report tests.xml).
#
# What differs from the template, and nothing else: the template's .gitattributes and .swiftlint.yml are left out (the
# first would change how git stores the files here, the second belongs to a static analysis that is no phase), the
# byte order mark of five source files is removed, ${studentParentWorkingDirectoryName} is assignment, the finalize
# step (chmod -R 777) is left out because the run needs no second user, and two things point SwiftPM at the image
# instead of the network. The mirror file tells SwiftPM to take the three packages of the test package from the
# clones the image holds (/opt/swift-deps), and HOME is a directory in the working directory so that SwiftPM's caches
# are written there and not under /root. TMPDIR is a directory inside the solution's, because SwiftPM compiles the
# package manifest into a program in TMPDIR and then runs it, which is the one place a Swift build executes a file
# it wrote; the exercise declares runs_compiled_programs (prune.json) and the base keeps execute on that directory only.
# Nothing is fetched: the run needs no network.
#
# `swift test` ends with a status that says whether the tests passed; the result is the JUnit report it writes
# (prune.json names it).
set -u
export HOME=/var/tmp/testing-dir/home
export TMPDIR=/var/tmp/testing-dir/assignment/.tmp
mkdir -p "${HOME}" "${TMPDIR}" assignment/.swiftpm/configuration
cp /opt/swift-deps/mirrors.json assignment/.swiftpm/configuration/mirrors.json || exit 2
cp -R test/Tests assignment/ || exit 2
cp test/Package.swift assignment/ || exit 2
cd assignment || exit 2
swift build || exit 1
swift test
