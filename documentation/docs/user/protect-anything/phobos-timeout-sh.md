---
title: "phobos-timeout.sh"
sidebar_position: 4
description: "The timeout layer: a wall-clock bound the command cannot step out of."
---

:::tip[Simple Story]
A clock on the wall ends the session.

The trick is not the clock. It is that nobody in the room can leave the room and carry on
working next door, which is what a process does when it starts a session of its own.
:::

The timeout layer reads the timeout from the specification and, where one is set, runs the rest
of the chain under GNU `timeout` and waits for it. Where none is set, the layer hands the chain
straight on, and no process-group lock is applied either, since there is no group kill to
escape.

## Running it on its own

```bash
${PHOBOS_HOME}/phobos-timeout.sh --config exercise.cfg -- ./slow-thing
```

| Option | What it is for |
| --- | --- |
| `--config <file>` | A configuration to build the specification from. Repeatable. |
| `--spec-parent <dir>` | Where the specification directory is made. The default is `/var/tmp`. |
| `--tail-flags-file <file>` | The tail flags file to apply. |
| `--timeout-bin <path>` | The timeout program to use. The default is `timeout` on `PATH`. |
| `--pgroup-lock-bin <path>` | The process-group lock to apply. |
| `--debug` | Report what the layer builds and runs. |

## How the bound is applied

```
timeout --kill-after=5s <timeout>s phobos-pgroup-lock -- <the rest of the chain>
```

Three parts of that line carry weight.

**No `--foreground`.** GNU `timeout` therefore puts the command in a new process group and
signals the whole group, so the kill reaches the command's children too.

**`--kill-after=5s`.** A command that ignores `SIGTERM` is stopped by the `SIGKILL` that
follows. That escalation only fires while the timeout's own child is still alive, which is why
the layers below keep themselves alive across `SIGTERM` and put the command itself back to the
default disposition before running it.

**`phobos-pgroup-lock` first.** The lock installs a seccomp filter that refuses `setsid` and
`setpgid` and then becomes the rest of the chain, so the filter is inherited by the whole group
and nothing in it can leave the group the kill targets. Where the lock is missing or not
executable, the layer ends the run with `PHB-ERUNTIME` rather than running a timed command that
could outlive its limit through a detached child.

The connect guard refuses the same two calls for the command it supervises, and that cover
belongs to the network layer. The lock is the timeout layer's own, so a run with the network
restriction disabled keeps the group kill unescapable.

## What counts as a timeout

GNU `timeout` passes the command's own exit status through where it did not time out, and a
command killed by somebody else, the out-of-memory killer among them, ends with the same 137 as
the escalation. The status alone therefore decides nothing.

A run is reported as `PHB-ETIMEOUT` with exit status 14 only where the status is 124 or 137
**and** the run lasted at least its timeout. Anything else passes through unchanged, including
a command's own 124 or 137.

The elapsed time is wall clock, read from `EPOCHREALTIME`. A clock stepped backwards during a
run can make a real expiry look too short, in which case the status passes through without the
timeout label; the run itself is never extended by it.

## How a timeout is spelled

A timeout is a number of seconds, either whole or with exactly three decimal places, so
`120` and `2.500` are both valid and `2.5` is not. Two spellings of one value compare as
numbers, and the specification records the canonical one, so `2` and `2.000` produce the same
run.

Every spelling of zero switches the timeout off and beats every finite value, within a file and
across files. Where several configurations name a finite timeout, the largest wins.

## Further reading

- [Timeout subsystem](/contributor/subsystems/timeout) — the same layer from the inside
- [timeout and the process-group lock](/contributor/technologies/timeout-and-the-process-group-lock) —
  the two mechanisms behind it
- [`[limits]`](/user/policy-reference/limits) — where a timeout is written
