---
title: "Writing an output file"
sidebar_position: 3
description: "Permitting one output directory without turning it into a general-purpose scratch space."
---

:::tip[Simple Story]
The work produces something, and it needs somewhere to put it.

Somewhere is one place, not the whole room.
:::

## The situation

The command produces output: a report, a build tree, a set of generated files. It needs a place
to write, and the rest of the filesystem must stay as it was.

## The policy fragment

```ini title="exercise.cfg"
[write]
/var/tmp/workspace

[create]
/var/tmp/workspace

[delete]
/var/tmp/workspace
```

The three sections are separate because the rights are separate. A command that only appends to
one known file needs `[write]` alone. A command that generates files needs `[create]` too. A
command that rebuilds in place, and therefore removes what was there, needs `[delete]` as well.

Where the tool writes to a temporary name and renames it into place, replace all three with one
section:

```ini title="exercise.cfg"
[restructure]
/var/tmp/workspace
```

[`[restructure]`](/user/policy-reference/restructure) carries create, delete and the REFER right
together, and REFER is what a rename across directories needs. Without it the kernel answers
`EXDEV`.

## What this still forbids

- reading the directory, which needs [`[read]`](/user/policy-reference/read) as well where the
  tool lists its own output
- creating a socket or a named pipe there, which is
  [`[create-ipc]`](/user/policy-reference/create-ipc)
- creating a symbolic link there, which is
  [`[create-symlink]`](/user/policy-reference/create-symlink)
- creating a device node, which no section grants
- every other path on the machine

## The tempting wrong version

```ini title="wrong.cfg"
[write]
/var/tmp
```

Naming the parent because the workspace does not exist yet makes every other run's scratch
space writable. Name the directory itself.

:::warning[A missing directory is created as a file]
Phobos materialises a missing changeable path, since a Landlock rule needs an existing path to
open, and it creates an empty **regular file**. A trailing slash does not help: the policy
merge canonicalises every path first and strips it. Make the directory before the run, or have
the command create it under a parent the policy already grants.
:::

The second tempting version is subtler:

```ini title="also-wrong.cfg"
[write]
/var/tmp/workspace/report.txt
```

That is correct where the file is the only thing written and it already exists. Where the tool
writes `report.txt.tmp` first, the run fails, because the create right on the directory is
missing.

## Notes

- A changeable path that is a symbolic link with no target is refused with `PHB-EPOLICY`:
  materialising it would write wherever it points.
- A changeable path that cannot be created is kept rather than dropped, so `phobos-landlock`
  refuses it with a clear message instead of the run failing later.
- The run's specification directory must lie outside every write path. The default parent is
  `/var/tmp`, and a policy that would make it writable is refused, so a workspace directly at
  `/var/tmp` is worth avoiding. Use a named subdirectory, as above, or move the specification
  with `--spec-parent`.
