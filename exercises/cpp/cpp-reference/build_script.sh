#!/bin/bash
# The C++ reference exercise for the layer pruner: the files of Artemis's C++ template (ls1intum/Artemis,
# src/main/resources/templates/c_plus_plus, commit b142d99f4106f4e7656ee4aff41bc68851aef192), laid out as Artemis
# lays out a build: the solution under assignment/ and the tester beside it in test/, which gets its own
# assignment/ because its CMakeLists.txt adds the solution as a subdirectory. The phases are those of
# templates/phases/c_plus_plus/default.yaml, in order: set up the build environment, compile, test.
#
# What differs from the template, and nothing else: ${studentParentWorkingDirectoryName} is assignment (in
# test/CMakeLists.txt), the template's .gitattributes and .gitignore are left out, the step that gives the files to
# the user the build runs as (chown, runuser) is left out because the run needs no second user, and the step that
# installs requirements.txt is left out because the template has none.
# The timeouts of TestConfigure, TestCompile and TestCatch2 are 120 seconds, not the template's 10: the layer pruner
# observes every system call with strace, which makes CMake's configure step about seven times slower, and a test
# that the observation alone ends would be pruned as if the sandbox had refused something.
# ASAN_OPTIONS is set to detect_leaks=0 for the same reason: the tester builds the program with AddressSanitizer,
# whose leak check at exit aborts under any tracer ("LeakSanitizer does not work under ptrace"). Artemis's GCC
# template sets the same option in its own Tests.py; the C++ template does not.
#
# The tester ends with status 0 or 1 as the template's phases do; the result is the JUnit report it writes
# (prune.json names it).
set -u
export ASAN_OPTIONS=detect_leaks=0
cp -R assignment test/assignment || exit 2
cd test || exit 2
mkdir -p test-reports
python3 Tests.py --only compile || exit 1
python3 Tests.py --only test
