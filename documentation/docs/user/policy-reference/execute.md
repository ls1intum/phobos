---
title: "[execute]"
sidebar_position: 2
description: "One path per line, granted the right to execute a file beneath it."
---

:::tip[Simple Story]
A drawer that opens is not a tool you may switch on.

Running a program is a permission of its own, and a tree that holds programs needs both: the
right to read them and the right to run them.
:::

## Position in the example policy file

The section documented on this page is marked in red. Every page in this section shows the same
example file, so reading them in order walks it from top to bottom.

```ini title="exercise.cfg"
# Every section this reference documents, gathered in one file so that each page can
# point at its own. A real policy names only what its command needs.

[read]
/srv/reference-data
/opt/toolchain

# policy-focus-start
[execute]
/opt/toolchain
# policy-focus-end

[write]
/var/tmp/workspace

[create]
/var/tmp/workspace

[delete]
/var/tmp/workspace

[create-ipc]
/var/tmp/workspace/run

[create-symlink]
/var/tmp/workspace/build

[restructure]
/var/tmp/workspace

[connect]
allow 192.0.2.10:443
allow repo.example.org:443
allow 203.0.113.53:53 udp

[bind]
allow 8080
allow 5353 udp

[accept]
expose 18080 to 8080 from 198.51.100.0/24

[limits]
timeout=120
mem_mb=2048
nproc=256
nofile=1024
fsize_mb=512
cpu=100
```

That file is a catalogue rather than a working configuration. Three of its entries change what
a run needs, and [the Policy Reference index](index.md) says which.

## Syntax

One path per line.

```ini
[execute]
/opt/toolchain
```

## What it grants

| Landlock right | What it permits |
| --- | --- |
| `LANDLOCK_ACCESS_FILESYSTEM_EXECUTE` | executing a file |

The rule carries the letter `x`, and it applies to the path and everything beneath it.

## What enforces it

The filesystem layer emits the same path as `--rights=x <path>`. A path named in several sections gets one rule
per section, each carrying the union of the letters, so `--rights=rx <path>` twice for a path in
`[read]` and `[execute]`, which Landlock unions. Landlock refuses an `execve` of a file beneath a path that
holds no execute right.

## Notes

**A program tree needs both sections.** The loader reads the program image and the shared
objects beside it, so a tree named only in `[execute]` fails at the first open. The shipped
base policies name the same system trees in both sections for exactly this reason.

**An interpreter is the executable, the script is the data.** Running `python3 build.py` needs
`[execute]` on the interpreter and `[read]` on the script.

**Phobos refuses an execute path that does not exist in a task configuration**, and one with
`*`, `?` or `[` in it anywhere, the same way it refuses a read path. A shipped base policy can
name an execute path the image lacks, and Phobos drops that entry without a word.

## Further reading

- [`[read]`](read.md): the other half of a program tree
- [Running a program tree](/user/policy-cookbook/running-a-program-tree): the recipe
