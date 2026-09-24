---
title: "[write]"
sidebar_position: 3
description: "One path per line, granted the right to write into an existing file and to shorten it."
---

:::tip[Simple Story]
Replacing what is on a sheet of paper is not the same as adding a sheet, and neither is the
same as throwing one away.

Phobos keeps the three apart, so a policy that only needs one grants only that one.
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

[execute]
/opt/toolchain

# policy-focus-start
[write]
/var/tmp/workspace
# policy-focus-end

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
[write]
/var/tmp/workspace
```

## What it grants

| Landlock right | What it permits |
| --- | --- |
| `LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE` | writing into an existing file |
| `LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE` | shortening a file, from version 3 |

The rule carries the letter `w`. It does **not** permit creating a file, deleting one, or
renaming anything: those are [`[create]`](create.md), [`[delete]`](delete.md) and
[`[restructure]`](restructure.md).

## What enforces it

`phobos-filesystem.sh` materialises the path before the rule is built, because a Landlock rule
needs an existing path to open. A path that does not exist is created as an empty **regular
file**. The rule is then emitted as `--rights=w <path>`.

:::warning[A missing directory is created as a file]
The materialising step reads a trailing slash as "make a directory", and it never sees one: the
policy merge canonicalises every path first, and `realpath --canonicalize-missing
--no-symlinks` strips the slash. Make a directory before the run, or have the command create it
under a parent the policy already grants.
:::

## Notes

**A path that is a symbolic link with no target is refused.** Materialising it would follow the
link and write wherever it points, outside anything the policy named, so the run ends with
`PHB-EPOLICY` before anything is created.

**A changeable path that does not exist is kept, not dropped.** Where materialisation fails,
`phobos-landlock` refuses the path with a clear message rather than the run failing later with
`EACCES`.

**A changeable rule never follows a final symbolic link.** `phobos-landlock` opens such a path
with `O_NOFOLLOW`, so a rule that may change something cannot be redirected by a link a
command planted. Read-only rules still follow links, because system paths legitimately are
links.

**Without `TRUNCATE`, a read-only path is not safe from `truncate(2)`.** On a kernel below
Landlock version 3 the right does not exist, so it is not handled at all.
`phobos-landlock` says so before the run, and `--minimum-landlock-version 3` refuses such a
kernel instead.

## Further reading

- [Writing an output file](/user/policy-cookbook/writing-an-output-file) — the recipe
- [`[create]`](create.md), [`[delete]`](delete.md), [`[restructure]`](restructure.md) — the
  other three ways to change a tree
