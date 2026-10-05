---
title: "Reading a data tree"
sidebar_position: 1
description: "Permitting a directory of input to be read without granting anything else on it."
---

:::tip[Simple Story]
One drawer opens, and the papers in it cannot be changed, run or thrown away.
:::

## The situation

The command reads a directory of input, a corpus, a fixture set or a set of reference files,
and must not change it. Nothing in the tree is a program.

## The policy fragment

```ini title="exercise.cfg"
[read]
/srv/reference-data
```

That is the whole recipe. The entry covers the path and everything beneath it, because Landlock
grants a whole subtree.

## What this still forbids

- writing into any file in the tree, or shortening one
- creating anything in it, and deleting anything from it
- executing anything in it
- renaming or moving anything within it
- every path outside the tree that the base policy does not name

## The tempting wrong version

```ini title="wrong.cfg"
[read]
/srv/reference-data

[write]
/srv/reference-data
```

Adding `[write]` because the tool "opens the files" is the common mistake. Reading a file needs
the read right alone. A tool that rewrites its input is doing something worth knowing about,
and it needs [`[write]`](/user/policy-reference/write) on purpose.

The second tempting version is narrower, and it is refused outright:

```ini title="also-wrong.cfg"
[read]
/srv/reference-data/public
```

Where the base policy already grants `/srv/reference-data` more than `r`, the nested entry is a
strict subset of its ancestor and the run ends with `PHB-EPOLICY`. Landlock can never take a
right away further down a path.

## Notes

- A read path that does not exist ends the run with `PHB-EPOLICY` in a task configuration, and
  the message names the file and the line. The shipped base policies are exempt, because they
  name system paths an image can lack. Check the path exists when the run is built.
- Reaching a pathname UNIX socket beneath the tree rides with this right, through
  `RESOLVE_UNIX` on Landlock version 9 and later.
