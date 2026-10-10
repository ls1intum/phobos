#!/bin/bash
# The FACT reference exercise for the layer pruner: the files of Artemis's FACT template (ls1intum/Artemis,
# src/main/resources/templates/c/fact, commit b142d99f4106f4e7656ee4aff41bc68851aef192), laid out as Artemis lays
# out a build: the solution under assignment/ and the tester under test/. The phases are those of
# templates/phases/c/fact.yaml, in order: compile with the tester's Makefile, then run the tester.
#
# What differs from the template, and nothing else: ${studentParentWorkingDirectoryName} is assignment and
# ${testWorkingDirectory} is test; the step that gives a file to the user the build runs as (sudo chown) is left
# out, since the run needs no second user.
#
# The tester ends with status 0 whatever its tests found, as in the template, so the result is the JUnit report it
# writes (prune.json names it) and not the exit status.
set -u
mkdir -p test-reports

rm -f assignment/GNUmakefile
rm -f assignment/Makefile
cp -f test/Makefile assignment/Makefile || exit 2
make -C assignment exercise

cd test || exit 2
python3 Tests.py
rm Tests.py
rm -rf ./test || true
