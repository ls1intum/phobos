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
the policy's path sets into `--rights=LETTERS PATH` arguments for `phobos-landlock-filesystem-and-networksystem`, which
applies the Landlock ruleset and executes the command.

## Running it on its own

```bash
${PHOBOS_HOME}/phobos-filesystem.sh --config exercise.cfg -- ./gradlew test
```

Given one or more `--config` files, the layer builds a specification of its own through
`phobos-policysystem.sh`, the single parser, and then enforces only the filesystem. Nothing else is
applied: no timeout, no connect guard, and no resource limits unless `--resources-layer` names one. That is what makes it useful for
isolating a failure.

| Option | What it is for |
| --- | --- |
| `--config <file>` | A configuration to build the specification from. Repeatable. |
| `--spec-parent <dir>` | Where the specification directory is made. The default is `/var/tmp`. |
| `--tail-flags-file <file>` | The tail flags file to apply. |
| `--no-landlock` | Run the command with no Landlock ruleset. |
| `--landlock-bin <path>` | The `phobos-landlock-filesystem-and-networksystem` program to use. |
| `--resources-layer <path>` | Start the resource layer as the last step before `phobos-landlock-filesystem-and-networksystem`. |
| `--reporter-bin <path>` | The report-only supervisor that reports each blocked action. |
| `--no-own-reporter` | Start no reporter of the layer's own. `phobos.sh` passes it when the network layer is on, whose connect guard is then the run's one supervisor. |
| `--group-lock-above` | The timeout layer's group lock is above this layer, so the reporter answers and reports the calls the lock refuses outright. `phobos.sh` passes it exactly when it applies the lock. |
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
appends to the `phobos-landlock-filesystem-and-networksystem` argument vector unchanged. It ships as `TailPhobos.cfg` and
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

This layer drops a read or execute path that does not exist quietly, because the shipped base
policies name system paths an image can lack. A task configuration never gets that far with
one: the policy program refuses it when it builds the specification. A changeable path that does not exist is kept, so
`phobos-landlock-filesystem-and-networksystem` refuses it with a clear message rather than the run failing later.

## Reporting what the layer blocks

The layer runs the command as a child, and the command's standard error is the layer's own:
nothing copies or counts it. With the network layer off (`-nnr`), or with this layer on its own,
the layer starts a report-only supervisor. Standard error then carries one line for each distinct
blocked action that the supervisor can attribute with certainty, for example:

```
Phobos Security Error: the program tried to illegally read the File '/etc/shadow' but was blocked by Phobos.
```

- The lines cover the refusals of Landlock that the supervisor can attribute with certainty. When
  the timeout layer applies a timeout, they cover the foreign-ABI calls that the group lock refuses,
  and `setsid` and `setpgid` where the supervisor cannot continue a call. Where it can, it answers
  those two from its ledger of virtual groups and prints nothing.
- When the run ends, one `Phobos Security Summary` line counts what the supervisor decided, per
  layer. The line appears only after a blocked action, and the words a command prints itself count
  for nothing.
- The layer words a resource limit that the command hit. Status 153 gives `... exceed the File
  Size Limit of 1 MB ...`. Status 137 gives `... exceed the CPU Time Limit of 5 seconds ...`, but
  only when the processes the layer waited for used the whole CPU budget, because the kernel ends
  a command at its CPU limit with that status. A command that exits with 153 by itself gets the
  file size line too, which a shell cannot tell apart from the signal. The process, open file and
  memory limits show as errors the command handles, so they get no line.
- Every doubt ends in silence, so a run without such a line can still have been refused
  something.
- The supervisor quotes each path the way bash quotes it, and a run prints at most 100 such lines.
- The supervisor never lets a refused call succeed, and it never makes a permitted call fail. The
  one difference is that the group lock's refusals fail with `EACCES` instead of `ENOSYS`. If the
  supervisor dies, the calls it watches fail with `ENOSYS`, and nothing gains a right.
- When the kernel or the setup cannot support reporting, the supervisor prints a notice that
  names what goes unreported and why, such as `Phobos: filesystem denial reporting is off for
  this run, because ...`. The layer enforces the run all the same. On a kernel older than Linux
  6.6 the supervisor says once that it cannot wake synchronously, which only slows reporting down.
- With the network layer on, the connect guard is the run's one supervisor and prints these lines
  itself, together with its own, so the layer starts no second supervisor.

If the supervisor cannot read the command's exit status, the run ends with `PHB-ESTATUS` (16)
instead of reporting a success that it cannot vouch for.

## Further reading

- [Filesystem subsystem](/contributor/subsystems/filesystem): the same layer from the inside
- [Landlock](/contributor/technologies/landlock): the kernel mechanism and its versions
- [Policy Reference](/user/policy-reference/): every filesystem section in full
