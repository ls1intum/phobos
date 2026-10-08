---
title: "The Ares 2 policy file"
sidebar_position: 4.5
description: "How Phobos reads a security policy written for Ares 2, what each key becomes, and what Phobos refuses."
---

:::tip[Simple Story]
One policy file, read by two guards.

Ares 2 stands inside the Java Virtual Machine (JVM) and Phobos stands around it. Phobos reads the
Ares 2 file for what the operating system can enforce, grants exactly that, and says in one line
what it left to Ares.
:::

A `--config` file whose name ends in `.yaml` or `.yml` is read as an
[Ares 2](https://github.com/ls1intum/Ares2) security policy, version 1. Every other `--config`
file is read as a Phobos policy. Each reader refuses the other's format, so a misnamed file ends
the run with `PHB-EPOLICY` and nothing misreads it.

```bash
${PHOBOS_HOME}/phobos.sh --config SecurityPolicy.yaml --project-root /var/tmp/testing-dir -- ./gradlew test
```

An imported file is an exercise configuration. Phobos folds it on top of the base policy exactly
as it folds a Phobos policy, so it adds to the base and never takes anything away from it.

## How the file is read

Phobos reads the YAML as a strict subset. It refuses, with the line, anything two YAML readers
could read differently: anchors, tags, block scalars, `yes`, `010`, a tab, an escape other than
`\\` and `\"`, and invalid UTF-8. Quote a value that holds text.

## The programming language configuration chooses the base

The key `theFollowingProgrammingLanguageConfigurationIsUsed` names a file,
`language-configurations/<NAME>.cfg`, beside `phobos-policysystem.sh`. That file does three things.

| It | What that means |
| --- | --- |
| lists base policies | a run under it folds those bases, and not every `Base*.cfg` the image ships |
| says how Phobos determines each placeholder | `${java.home}` and the like become paths, each by `environment`, `command-ancestor`, `fixed` or `password-database home`, and only when a path uses it |
| can add `[connect]` rules | loopback rules without a port, and nothing else |

This file is the one place a programming language enters Phobos. The image ships the four
`JAVA_USING_GRADLE_*` configurations. Phobos refuses a configuration with no file, the
`JAVA_USING_MAVEN_*` ones among them for now. Every Ares policy of one run must name the same
configuration.

## What each key becomes

| Ares 2 | Phobos |
| --- | --- |
| `readAllFiles` | [`[read]`](policy-reference/read.md) |
| `overwriteAllFiles` | [`[write]`](policy-reference/write.md) |
| `createAllFiles` | [`[create]`](policy-reference/create.md) and [`[create-symlink]`](policy-reference/create-symlink.md), since Ares counts a symbolic link as created |
| `executeAllFiles` | [`[execute]`](policy-reference/execute.md) |
| `deleteAllFiles` | [`[delete]`](policy-reference/delete.md) |
| `createAllFiles` with `deleteAllFiles` | [`[restructure]`](policy-reference/restructure.md) as well, since Ares lets such an entry move files |
| a network entry with all three flags true | a [`[connect]`](policy-reference/connect.md) rule for TCP, and the same rule for UDP. `onThePort: 0` means every port of loopback. |
| a network entry with all three flags false | nothing |
| the tightest `timeout` | [`[limits]`](policy-reference/limits.md) `timeout`, converted from milliseconds exactly and never rounded |

## Where a path starts

`onThisPathAndAllPathsBelow` starts at the project root. That is `--project-root` where you give
it, otherwise the last `--chdir` of the tail flags. With neither, Phobos refuses a relative path
and `${PROJECT_ROOT}`. The project root must be the directory the build tool starts the test JVM
in, because Ares resolves the same paths from there. It must be the real path of a project
directory as well. Phobos refuses `/`, a root that reaches its directory through a symbolic link
and a root with a `..` segment. The rule applies to `--project-root` always, and to the last
`--chdir` of the tail flags where a path needs the root.

## What Phobos refuses

Each refusal names the file and the line.

- a path of `*`, a backslash or a `..` segment
- a placeholder the configuration does not name
- a path that does not exist, in every section, since Ares does not say whether a path is a file
  or a directory
- a path that reaches the project root through a symbolic link, or through another name for the
  root, and so resolves to somewhere other than where it reads. The submission's checkout usually
  sits at the project root, and a link it commits there steers the grant to a place the policy
  never named. Write the real path instead. A link that leads away from the root, such as `/bin`
  to `/usr/bin`, stays allowed.
- a network entry that grants only some of its three flags
- a host name that ends in a dot
- a host other than loopback with port 0
- a timeout of 0
- any version but 1
- any key the schema does not have

## Phobos adds, Ares narrows

Phobos writes nothing for an entry the base already grants on the same path or an ancestor, after
it resolves both through their symbolic links, because Landlock adds nothing for it. The
summary line counts it. Ares enforces the narrower intent of such an entry, "this one file and
nothing else", inside the JVM, and Phobos does not.

Each imported file gets one summary line on standard error. It names what Phobos does not
enforce: command entries, thread entries, package entries and the exemption Ares gives test
classes.

## Two things that surprise

- An imported timeout bounds the whole run, the build tool included, and not only the code Ares
  supervises.
- A configuration's `allow localhost udp` lets every UDP rule an import brings start on a kernel
  below Landlock version 10, held by the connect guard alone. For such a run it permits UDP to
  every loopback port.

## Related pages

- [Importing an Ares 2 policy](policy-cookbook/importing-an-ares-2-policy.md) walks one
  exercise through it.
- [Troubleshooting](troubleshooting.md) explains the exit status `11`, which every refusal above
  ends the run with.
