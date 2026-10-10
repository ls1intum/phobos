---
title: "Importing an Ares 2 policy"
sidebar_position: 7
description: "Running an exercise under the security policy it already carries for Ares 2, and what that grants."
---

:::tip[Simple Story]
The exercise already says what its tests can touch. Phobos reads that note instead of a second one.
:::

## The situation

A Java exercise carries a `SecurityPolicy.yaml` for Ares 2, and the grader wants the operating
system to hold the same line. A second policy written by hand lets the two drift.

## The policy fragment

The exercise's own file is the whole recipe. This is the shape of the Artemis Java test template:

```yaml title="SecurityPolicy.yaml"
thisPolicyFileCompliesToThePolicyVersion: 1
regardingTheSupervisedCode:
  theFollowingProgrammingLanguageConfigurationIsUsed: JAVA_USING_GRADLE_ARCHUNIT_AND_ASPECTJ
  theSupervisedCodeUsesTheFollowingPackage: "de.phobos.reference"
  theMainClassInsideThisPackageIs: "Client"
  theFollowingClassesAreTestClasses:
    - "de.phobos.reference.AttributeTest"
    - "de.phobos.reference.ClassTest"
    - "de.phobos.reference.ConstructorTest"
    - "de.phobos.reference.MethodTest"
    - "de.phobos.reference.SortingExampleBehaviorTest"
  theFollowingResourceAccessesArePermitted:
    regardingFileSystemInteractions: [ ]
    regardingNetworkConnections: [ ]
    regardingCommandExecutions: [ ]
    regardingThreadCreations: [ ]
    regardingPackageImports: [ ]
    regardingTimeouts: [ ]
```

Name it with `--config` and say where the project is:

```bash
${PHOBOS_HOME}/phobos.sh --config SecurityPolicy.yaml --project-root /var/tmp/testing-dir -- ./gradlew test
```

The programming language configuration in the first lines picks the base policy. This file adds
nothing to that base, so the run is held to the base alone, and Phobos prints one summary line on
standard error that says so.

Add an entry to grant one more file. Phobos reads its path from the project root:

```yaml title="SecurityPolicy.yaml"
    regardingFileSystemInteractions:
      - onThisPathAndAllPathsBelow: "data/input.txt"
        readAllFiles: true
        overwriteAllFiles: false
        createAllFiles: false
        executeAllFiles: false
        deleteAllFiles: false
```

That entry becomes `[read]` for `/var/tmp/testing-dir/data/input.txt`, and no other right.

## What this still forbids

- every path the base and the entries do not name
- a right the entry sets to `false`
- every host, because a network entry that grants nothing becomes nothing
- a run longer than the tightest `timeout` the file names, where it names one

## The tempting wrong version

```yaml title="wrong.yaml"
    regardingFileSystemInteractions:
      - onThisPathAndAllPathsBelow: "data/missing.txt"
        readAllFiles: true
```

Two things are wrong. Ares 2 expects all six keys of an entry, and the path does not exist. Phobos
refuses a missing path in every section, because it cannot tell whether a path is a file or a
directory, and the filesystem layer creates a missing changeable path as an empty file. The first
of the two that the reader meets ends the run with `PHB-EPOLICY`, and the message names the file
and the line.

## Notes

- A path the base already covers is not written, and the summary line counts it. Ares enforces its
  narrower intent inside the Java Virtual Machine (JVM).
- Phobos does not enforce command, thread or package entries, nor the exemption Ares gives test
  classes.
- The full list of keys and refusals is on [the Ares 2 policy file](../ares-2-policy.md).
