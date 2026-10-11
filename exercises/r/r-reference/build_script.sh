#!/bin/bash
# The R reference exercise for the layer pruner: the files of Artemis's R template (ls1intum/Artemis,
# src/main/resources/templates/r, commit b142d99f4106f4e7656ee4aff41bc68851aef192), laid out as Artemis lays out a
# build: the solution under assignment/ and the test package beside it in test/, which gets its own assignment/
# because its DESCRIPTION names the solution as local::./assignment. The three phases are those of
# templates/phases/r/default.yaml, in order: install, syntax_check, run_all_tests.
#
# What differs from the template, and nothing else: ${studentParentWorkingDirectoryName} is assignment, the test
# package is in test/, and R_LIBS_USER is a library inside the working directory, because the template installs
# into the image's site library, which a submission must not be able to overwrite. R finds a library named by
# R_LIBS_USER only when it exists, so it is created first. Nothing is fetched: the run needs no network.
#
# Rscript ends with status 0 or 1 as the template's phases do; the result is the JUnit report that test_local writes
# (prune.json names it) and not the exit status.
set -u
export R_LIBS_USER=/var/tmp/testing-dir/rlib
mkdir -p "${R_LIBS_USER}"
cp -R assignment test/assignment || exit 2
cd test || exit 2
Rscript -e 'remotes::install_local()' || exit 1
Rscript -e 'files <- list.files(".", pattern = "\\.[Rr]$", recursive = TRUE, full.names = TRUE); invisible(lapply(files, function(f) parse(file = f, keep.source = FALSE)))' || exit 1
Rscript -e 'library("testthat"); options(testthat.output_file = "junit.xml"); test_local(".", reporter = "junit")'
