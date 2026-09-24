---
title: "phobos-resources.sh"
sidebar_position: 5
description: "The resource layer: the rlimits the policy names, set for the command and nothing else."
---

:::tip[Simple Story]
The bench is a certain size, and the session has a budget.

The budget belongs to the work, never to the people carrying things in and out. A porter who
ran out of budget halfway would drop what the work had produced.
:::

The resource layer sets the resource limits the policy named and then replaces itself with the
rest of the chain, so `phobos-landlock` and the command inherit them.

## Running it on its own

```bash
${PHOBOS_HOME}/phobos-resources.sh --config exercise.cfg -- ./hungry-thing
```

| Option | What it is for |
| --- | --- |
| `--config <file>` | A configuration to build the specification from. Repeatable. |
| `--spec-parent <dir>` | Where the specification directory is made. The default is `/var/tmp`. |
| `--tail-flags-file <file>` | The tail flags file to apply. |
| `--debug` | Report which limits were set. |

## The limits

| Key | Set as | Bounds |
| --- | --- | --- |
| `mem_mb` | `ulimit -v`, in kilobytes | the virtual memory of the command and everything it starts |
| `nproc` | `ulimit -u` | the number of processes |
| `nofile` | `ulimit -n` | the number of open file descriptors |
| `fsize_mb` | `ulimit -f`, in 1024-byte blocks | the largest file that may be written |
| `cpu` | `ulimit -t`, in seconds | the processor time |

Each is optional, and a value of zero switches that limit off. A value that cannot be set ends
the run with `PHB-ERUNTIME` rather than running without a limit the policy asked for, and a
value too large to convert safely ends it with `PHB-EPOLICY`.

The layer re-reads the limits from the specification and validates them again rather than
trusting what an earlier stage wrote. A malformed value is refused with `PHB-EPOLICY`, so no
unchecked text reaches the arithmetic.

## Why the layer sits where it does

The resource layer is not a link of the chain the entry point assembles. The filesystem layer
starts it as the last step before `phobos-landlock`, which is what keeps the limits on the
command alone.

Everything Phobos runs beside the command stays outside them: the layer shells, the standard
error pass-through, the denial counter, and the connect guard's supervisor. A helper that met
the command's file-size, memory or processor-time limit would die, and the command's output
would go with it.

:::note[rlimits are not the hard cap]
Resource limits are self-imposed, exactly as Landlock is, which is why they hold inside an
ordinary unprivileged container. They are an in-process line of defence beside the cgroup caps
the container is started with, never a substitute for them. A fork bomb filling the process
table and a run filling the disk are the container's job.
:::

## Further reading

- [Resources subsystem](/contributor/subsystems/resources) — the same layer from the inside
- [rlimits](/contributor/technologies/rlimits) — the mechanism and its units
- [`[limits]`](/user/policy-reference/limits) — where a limit is written
