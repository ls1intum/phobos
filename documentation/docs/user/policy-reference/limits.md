---
title: "[limits]"
sidebar_position: 12
description: "The wall-clock timeout and the five resource limits a run is held to."
---

:::tip[Simple Story]
The session has a length and a budget.

Both belong to the work itself. Nothing Phobos runs beside it shares them, so a helper can
never run out of budget and take the work's output with it.
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

# policy-focus-start
[limits]
timeout=120
mem_mb=2048
nproc=256
nofile=1024
fsize_mb=512
cpu=100
# policy-focus-end
```

That file is a catalogue rather than a working configuration. Three of its entries change what
a run needs, and [the Policy Reference index](index.md) says which.

## Syntax

One `key=value` per line. Each key has to be named; a bare value is refused.

```ini
[limits]
timeout=120
mem_mb=2048
```

| Key | Unit | Bounds | Applied as |
| --- | --- | --- | --- |
| `timeout` | seconds | the wall clock of the whole run | GNU `timeout` |
| `mem_mb` | megabytes | virtual memory | `ulimit -v` |
| `nproc` | count | processes | `ulimit -u` |
| `nofile` | count | open file descriptors | `ulimit -n` |
| `fsize_mb` | megabytes | the largest file that may be written | `ulimit -f` |
| `cpu` | seconds | processor time | `ulimit -t` |

An unknown key is refused with `PHB-EPOLICY` rather than ignored, so a typo in a limit cannot
leave the run unrestricted.

## How a value is written

A timeout is a number of seconds, either whole or with exactly three decimal places: `120` and
`2.500` are valid, `2.5` is not. Every other limit is a non-negative whole number, read in base
ten, so a leading zero is not taken for an octal number.

**A zero switches that limit off**, and it beats every finite value, within a file and across
files. Where several configurations name a finite value for the same limit, the largest wins.
The rule is the same for the timeout and for each resource limit, so the order the
configurations are read in does not matter.

## What enforces it

The timeout is written into the specification and applied by
[phobos-timeout.sh](/user/protect-anything/phobos-timeout-sh), which runs the rest of the chain
under GNU `timeout` and waits.

The five resource limits are written as one `key=value` per line and applied by
[phobos-resources.sh](/user/protect-anything/phobos-resources-sh), which the filesystem layer
starts as the last step before `phobos-landlock`. They therefore bind the command and
everything it starts, and none of the helpers Phobos runs beside it.

## Notes

**A limit that cannot be set ends the run.** `PHB-ERUNTIME`, rather than a run without a limit
the policy asked for.

**A memory or file-size value too large to convert safely ends the run** with `PHB-EPOLICY`.
The ceiling is the largest megabyte value whose kilobytes still fit signed 64-bit arithmetic.

:::note[These are not the hard caps]
Resource limits are self-imposed and hold inside an ordinary unprivileged container. The hard
caps a machine needs against a fork bomb or a run that fills the disk are cgroup limits the
container is started with. Phobos cannot set those for itself.
:::

## Further reading

- [Setting time and memory budgets](/user/policy-cookbook/setting-time-and-memory-budgets) —
  the recipe
- [rlimits](/contributor/technologies/rlimits) — the mechanism and its units
- [timeout and the process-group lock](/contributor/technologies/timeout-and-the-process-group-lock)
