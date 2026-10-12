#!/bin/bash
# The build script of the exercise template the submissions suites use: it runs the student's
# assignment/solution.sh and writes a JUnit report with one test case that passes when the solution
# ends with 0. Without a solution it prints Gradle's NO-SOURCE line and writes no report, which the
# layer pruner's baseline refuses, so a submission without one is aborted deterministically.
set -u

REPORT_DIRECTORY=build/test-results/test

if [[ ! -f assignment/solution.sh ]]; then
  echo "> Task :compileJava NO-SOURCE"
  exit 0
fi
mkdir -p "$REPORT_DIRECTORY"
if bash assignment/solution.sh > /dev/null 2>&1; then
  outcome='<testcase classname="Solution" name="runs"/>'
else
  outcome='<testcase classname="Solution" name="runs"><failure/></testcase>'
fi
printf '<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="Solution" tests="1">\n  %s\n</testsuite>\n' "$outcome" \
  > "${REPORT_DIRECTORY}/TEST-Solution.xml"
