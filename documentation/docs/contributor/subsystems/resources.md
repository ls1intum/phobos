---
title: "Resources"
sidebar_position: 5
description: "The layer that sets the rlimits, and the reason it is started where it is."
---

:::tip[Simple Story]
The smallest layer, and the one whose position carries all the meaning.

Two lines of work, done at exactly the right moment.
:::

## What it does

`phobos-resources.sh` reads `limits.conf` from the specification, sets each limit in its own
shell, and then replaces itself with the rest of the chain, so `phobos-landlock` and the
command inherit them.

## What is in it

| File | Purpose |
| --- | --- |
| `phobos-resources.sh` | the layer: read, validate, apply, `exec` |
| `phobos-policy-parse.sh` | `read_limits_conf` and `apply_resource_limits`, shared with the parser |
| `phobos-constants.sh` | the unit conversions and the largest safe megabyte value |

## Where it sits, and why

It is **not** a link of the chain `phobos.sh` assembles. The filesystem layer starts it as the
last step before `phobos-landlock`:

```
phobos-filesystem.sh -> phobos-resources.sh -> phobos-landlock -> the command
```

That is the whole design. A limit set any earlier would bind the helpers too: the layer shells,
the standard error pass-through, the denial counter and the connect guard's supervisor. A
helper that met the command's file-size, memory or processor-time limit would die, and the
command's output would go with it.

## Validated twice, deliberately

The filesystem layer calls `read_limits_conf` before it materialises any write path, so a
malformed value is refused before that layer changes anything on disk. The resource layer reads
the same file again when it applies the values rather than trusting what an earlier stage
wrote. Neither pass lets unchecked text reach the arithmetic in `apply_resource_limits`.

## The conversions

| Key | Applied as | Conversion |
| --- | --- | --- |
| `mem_mb` | `ulimit -v` | megabytes times 1024 |
| `nproc` | `ulimit -u` | none |
| `nofile` | `ulimit -n` | none |
| `fsize_mb` | `ulimit -f` | megabytes times 1024, in 1024-byte blocks |
| `cpu` | `ulimit -t` | none |

Every value is read in base ten. A megabyte value above `PHB_LARGEST_MEGABYTES`, which is the
largest whose kilobytes still fit signed 64-bit arithmetic, is refused with `PHB-EPOLICY`,
because a larger one would wrap to a small or negative limit. A limit that cannot be set ends
the run with `PHB-ERUNTIME`.

A value of zero switches that limit off, and it is not applied at all.

## Known gaps

**`RLIMIT_NPROC` counts for the real user across the system**, not for this process tree. A
machine running several protected runs as one user shares the count, which is one of the
reasons the hard cap belongs to cgroups rather than here.

**There is no limit on the number of threads as such**, nor on the total memory a tree may
hold: `RLIMIT_AS` bounds one address space at a time.

## Further reading

- [rlimits](../technologies/rlimits.md) — the mechanism, the units and what they are not
- [phobos-resources.sh](/user/protect-anything/phobos-resources-sh) — the same layer, from the
  outside
- [`[limits]`](/user/policy-reference/limits) — where the values are written
