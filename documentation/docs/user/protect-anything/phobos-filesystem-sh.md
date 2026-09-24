---
title: "phobos-filesystem.sh"
sidebar_position: 2
description: "The filesystem layer: how the path sets become Landlock rules, and how to run it on its own."
---

:::tip[Simple Story]
This is the layer that decides which drawers open.

It reads the eight lists of paths the policy produced, works out which rights each path holds
in the end, hands them to the kernel, and then runs your command inside what is left.
:::

The filesystem layer is the last link of the chain and the one that runs the command. It turns
the policy's path sets into `--rights=LETTERS PATH` arguments for `phobos-landlock`, which
applies the Landlock ruleset and executes the command.

## Running it on its own

```bash
${PHOBOS_HOME}/phobos-filesystem.sh --config exercise.cfg -- ./gradlew test
```

Given one or more `--config` files, the layer builds a specification of its own through
`phobos-policy.sh`, the single parser, and then enforces only the filesystem. Nothing else is
applied: no timeout, no connect guard, no resource limits. That is what makes it useful for
isolating a failure.

| Option | What it is for |
| --- | --- |
| `--config <file>` | A configuration to build the specification from. Repeatable. |
| `--spec-parent <dir>` | Where the specification directory is made. The default is `/var/tmp`. |
| `--tail-flags-file <file>` | The tail flags file to apply. |
| `--no-landlock` | Run the command with no Landlock ruleset. |
| `--landlock-bin <path>` | The `phobos-landlock` program to use. |
| `--resources-layer <path>` | Start the resource layer as the last step before `phobos-landlock`. |
| `--debug` | Report what the layer builds and runs. |

Called from `phobos.sh`, it receives a specification directory in place of the `--config`
files and behaves the same way from there on.

## From sections to rights

Each filesystem section of a policy grants its own rights, named by one letter each. Most
sections carry a single letter; `[restructure]` carries three, and the letter `r` stands for
three kernel rights rather than one:

| Section | Letter | Right |
| --- | --- | --- |
| `[read]` | `r` | read a file, list a directory |
| `[execute]` | `x` | execute a file |
| `[write]` | `w` | write into an existing file, and shorten it |
| `[create]` | `m` | create regular files and directories |
| `[delete]` | `d` | delete files and directories |
| `[create-ipc]` | `p` | create sockets and named pipes |
| `[create-symlink]` | `l` | create symbolic links |
| `[restructure]` | `m`, `d`, `f` | create, delete, and move or rename across directories |

A path that appears in several sections holds the union of their letters. A path that appears
in none is not listed at all and stays denied. The letter `i`, for `ioctl` on a character or
block device, has no policy section: nothing you write in a configuration file grants it.

The one route to a letter no section produces is the tail flags file, whose lines this layer
appends to the `phobos-landlock` argument vector unchanged. It ships as `TailPhobos.cfg` and
today carries the run's working directory alone. It is part of the image rather than of a task
configuration, so a `--rights=` written there is a change to the shipped policy.

## Three things the layer does before the kernel sees anything

**It materialises the changeable paths first.** A Landlock rule needs an existing path to open,
so a write, create, delete, inter-process communication (IPC), symbolic-link or restructure
path that does not exist yet is created as an empty regular file. A path that is a symbolic
link with no target is refused instead, because materialising it would write wherever it
points.

:::warning[Create a directory before you name it]
The materialising step reads a trailing slash as "make a directory", and it never sees one: the
policy merge canonicalises every path first, and `realpath --canonicalize-missing
--no-symlinks` strips the slash. A directory that does not exist yet is therefore created as an
empty **file**, and the command then fails to create anything inside it. Make the directory
before the run, or have the command's own first step make it under a parent the policy already
grants.
:::

**It folds the paths that name one tree.** Two spellings can name the same directory, since
`/bin` is a symbolic link to `/usr/bin` in the run-phase image. Landlock anchors a rule on the
inode, so it sees one target carrying both entries' rights. The layer resolves every path
through its symbolic links and unions the rights per target, and it says so on standard error
where the union is wider than one of the spellings asked for.

**It refuses a hierarchy Landlock could not hold.** Landlock adds the rights of every rule
along a path and can never take one away. A nested path granted a strict subset of an
ancestor's rights therefore states a restriction that will not hold, and the run ends with
`PHB-EPOLICY` rather than starting with a policy that reads stricter than it is. Different
rights, with neither side a subset, are the ordinary shape of a workspace and stay allowed;
the effective set is the union.

A read or execute path that does not exist is dropped quietly, because a system path absent
from this image is not a policy error. A changeable path that does not exist is kept, so
`phobos-landlock` refuses it with a clear message rather than the run failing later.

## Counting denials

The layer runs the command as a child rather than replacing itself with it, so that it can
watch the command's standard error. The output passes through unchanged, and a copy goes to a
counter that matches two patterns: `Permission denied`, `EACCES` or `EROFS` for the
filesystem, and the resolver and unreachable-network messages for the network. Where either
count is above zero, the layer prints `PHB-EDENY` with both.

Nothing is written to a file, so the counts cannot be tampered with from inside the sandbox.
The command inherits neither descriptor, so it can neither feed the counter nor keep it alive.
The wait for the counts is bounded, and a run whose counts do not arrive reports none; the exit
status never changes either way.

## Further reading

- [Filesystem subsystem](/contributor/subsystems/filesystem) — the same layer from the inside
- [Landlock](/contributor/technologies/landlock) — the kernel mechanism and its versions
- [Policy Reference](/user/policy-reference/) — every filesystem section in full
