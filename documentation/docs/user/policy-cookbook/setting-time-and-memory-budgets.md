---
title: "Setting time and memory budgets"
sidebar_position: 6
description: "Bounding a run in wall-clock time, memory, processes, open files, file size and processor time."
---

:::tip[Simple Story]
The session ends at a fixed time, and the bench is a fixed size.

Both belong to the work. Nothing Phobos runs beside the work shares its budget, so a helper
cannot run out and take the work's output with it.
:::

## The situation

The run has to end. A command that loops, allocates without bound, forks without bound or
writes without bound must be stopped rather than waited for.

## The policy fragment

```ini title="exercise.cfg"
[limits]
timeout=120
mem_mb=2048
nproc=256
nofile=1024
fsize_mb=512
cpu=100
```

Every key is optional, and each bounds one thing: wall-clock seconds for the whole run, virtual
memory in megabytes, the number of processes, the number of open file descriptors, the largest
file that may be written in megabytes, and processor seconds.

Two of them look alike and are not. `timeout` is wall clock and stops the run from outside,
through GNU `timeout`. `cpu` is processor time and is enforced by the kernel against the
process, so a command that sleeps burns the first and not the second.

## What this still forbids

Nothing new. This section adds bounds rather than permissions, and it has no effect on which
paths or hosts the command may reach.

## The tempting wrong version

```ini title="wrong.cfg"
[limits]
120
```

A bare value is refused: each key has to be named. An unknown key is refused too, so a
misspelt `mem-mb` ends the run with `PHB-EPOLICY` rather than leaving the memory unbounded.

The second tempting version silently does the opposite of what it looks like:

```ini title="also-wrong.cfg"
[limits]
timeout=0
```

Zero switches the limit off, and it beats every finite value any other configuration names. A
base policy that sets `timeout=600` and a task configuration that sets `timeout=0` produce a
run with no timeout at all.

The third is a spelling:

```ini title="still-wrong.cfg"
[limits]
timeout=2.5
```

A timeout is whole seconds or seconds with exactly three decimal places. Write `2.500`.

## Notes

- Where several configurations name a finite value for one limit, the largest wins. The order
  they are read in therefore does not matter.
- A limit that cannot be set ends the run with `PHB-ERUNTIME` rather than running without it.
- The timeout is reported as `PHB-ETIMEOUT`, exit status 14, only where GNU `timeout` says so
  and the run lasted at least its limit. A command's own 124 or 137 passes through unchanged.
- These are not the hard caps. A fork bomb filling the process table and a run filling the disk
  are stopped by cgroup limits the container is started with, which Phobos cannot set for
  itself.
