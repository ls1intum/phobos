---
title: "rlimits"
sidebar_position: 6
description: "The per-process resource limits Phobos sets, their units, and what they are not."
---

:::tip[Simple Story]
The work gets a budget, and it is the work that carries it.

Everybody else in the room keeps their own, so a porter who runs out of budget never takes the
work's output with them.
:::

## What they are

Resource limits are a per-process ceiling the kernel enforces. Each has a soft limit, which a
process may lower freely, and a hard limit, which only a privileged process may raise. Lowering
a soft limit needs no privilege at all, exactly as Landlock and seccomp need none, which is why
Phobos can set them inside an ordinary unprivileged container. They are inherited across `fork`
and preserved across `execve`, so a limit set once binds the whole tree below it.

## The five Phobos sets

`phobos-resources.sh` reads the specification and applies each limit through the shell's
`ulimit`, which is the interface to `setrlimit` a shell offers.

| Key | `ulimit` | Resource | Unit conversion |
| --- | --- | --- | --- |
| `mem_mb` | `-v` | `RLIMIT_AS`, the virtual address space | megabytes to kilobytes |
| `nproc` | `-u` | `RLIMIT_NPROC`, processes for the real user | none |
| `nofile` | `-n` | `RLIMIT_NOFILE`, open file descriptors | none |
| `fsize_mb` | `-f` | `RLIMIT_FSIZE`, the largest file | megabytes to 1024-byte blocks |
| `cpu` | `-t` | `RLIMIT_CPU`, processor seconds | none |

Every value is read in base ten, so a leading zero is not taken for an octal number. A megabyte
value above the largest whose kilobytes still fit signed 64-bit arithmetic is refused, because
a larger one would wrap to a small or negative limit. A limit that cannot be set ends the run
rather than leaving it unbounded.

## Where they are set, and why it matters

The resource layer is the last step before `phobos-landlock`, started by the filesystem layer
rather than sitting in the outer chain. Everything Phobos runs beside the command therefore
stays outside the limits: the layer shells, the standard error pass-through, the denial
counter, and the connect guard's supervisor.

That is not tidiness. A helper that met the command's file-size, memory or processor-time limit
would die, and the command's output would go with it. The denial counter has small limits of
its own for the same reason, so a single endless line of standard error cannot grow it without
bound.

## What they are not

These are per-process ceilings, not machine-wide ones. `RLIMIT_NPROC` counts processes for the
real user identifier across the system, and `RLIMIT_AS` bounds one address space rather than
the total a tree may hold.

The hard caps a machine needs against a determined command are cgroup limits the container is
started with: `--memory`, `--pids-limit`, `--cpus` and a size-bounded scratch filesystem.
Phobos cannot set those for itself and does not assume they are set. The rlimits are the
in-process line beside them.

## Further reading

- [`getrlimit(2)`](https://man7.org/linux/man-pages/man2/getrlimit.2.html) — every resource and
  its semantics
- [`ulimit`](https://man7.org/linux/man-pages/man1/ulimit.1p.html) — the shell interface
- [`cgroups(7)`](https://man7.org/linux/man-pages/man7/cgroups.7.html) — the caps the container
  supplies
