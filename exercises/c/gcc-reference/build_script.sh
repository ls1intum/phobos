#!/bin/bash
# The GCC reference exercise for the layer pruner: the files of Artemis's GCC template (ls1intum/Artemis,
# src/main/resources/templates/c/gcc, commit b142d99f4106f4e7656ee4aff41bc68851aef192), laid out as Artemis lays
# out a build: the solution under assignment/ and the tester under test/. The phases are those of
# templates/phases/c/gcc.yaml, in order: set up the Makefile, compile, run the tester.
#
# What differs from the template, and nothing else: ${studentParentWorkingDirectoryName} is assignment and
# ${testWorkingDirectory} is test; the steps that give a file to the user the build runs as (sudo chown) and that
# install the tester's requirements (pip3, whose requirements.txt is empty) are left out, since the run needs
# neither a second user nor a package index.
#
# The tester ends with status 0 whatever its tests found, as in the template, so the result is the JUnit report it
# writes (prune.json names it) and not the exit status.
set -u
mkdir -p test-reports

shadowFilePath="../test/testUtils/c/shadow_exec.c"
foundIncludeDirs=$(grep -m 1 'INCLUDEDIRS\s*=' assignment/Makefile)
foundSource=$(grep -m 1 'SOURCE\s*=' assignment/Makefile)
foundSource="$foundSource $shadowFilePath"
rm -f assignment/GNUmakefile
rm -f assignment/makefile
cp -f test/Makefile assignment/Makefile || exit 2
sed -i "s~\bINCLUDEDIRS\s*=.*~${foundIncludeDirs}~; s~\bSOURCE\s*=.*~${foundSource}~" assignment/Makefile

gcc -c -Wall assignment/*.c

cd test || exit 0
python3 Tests.py || true
