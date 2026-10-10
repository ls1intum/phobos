---
title: "timeout and the process-group lock"
sidebar_position: 5
description: "GNU timeout, the process group it signals, and the seccomp filter that stops anything leaving that group."
---

:::tip[Simple Story]
A clock ends the session, and the ending reaches everybody in the room.

The one way out would be to walk into the next room and carry on. A filter refuses exactly that
move, so the clock cannot be escaped.
:::

## GNU timeout

`timeout` from GNU coreutils runs a command with a time limit, sends it a signal when the limit
passes, and reports a distinct exit status when it did so. Phobos uses three of its properties.

**No `--foreground`.** Without that option `timeout` puts the command into a process group of
its own and signals the **whole group**, so the ending reaches the command's children too. That
is the behaviour Phobos wants, and it is what makes the process-group lock necessary.

**`--kill-after=5s`.** A command that ignores `SIGTERM` is stopped by the `SIGKILL` that
follows. The escalation only fires while `timeout`'s own child is still alive, which shapes
everything below it: the layers that wait keep themselves alive across `SIGTERM`, and each
restores the default disposition for the command itself in a subshell just before running it,
so the `SIGKILL` reaches the command rather than a wrapper.

**Its exit status is a hint, not a verdict.** `timeout` answers 124 when it timed out, and the
escalation ends a command with 137. A command can produce either status on its own, and the
out-of-memory killer produces 137 too. Phobos therefore labels a run `PHB-ETIMEOUT` only where
the status is 124 or 137 **and** the wall clock says the run lasted at least its limit.

## The process-group lock

`phobos-seccomp-timeoutsystem` is a handful of Berkeley Packet Filter instructions and one
`execvp`. It refuses `setsid` and `setpgid`, refuses every non-native application binary interface (ABI) so that an alternate entry cannot reach those calls with different numbers, and
allows everything else. The refusal is a user notification to a listener the lock does not have,
so the kernel itself answers it with `ENOSYS`. A supervisor further down the chain, the connect
guard or the filesystem layer's report-only supervisor, traps the same calls with a listener of
its own, answers `EACCES` and reports them. In no state does the call run.

It is the first process under `timeout`, so its filter is inherited by the whole group and
nothing in the group can leave it. Without it, a command could call `setsid`, detach from the
group the kill targets, and outlive its limit.

It fails closed: where `PR_SET_NO_NEW_PRIVS` or the filter cannot be set, the command is
refused rather than run outside the lock. The timeout layer refuses to run at all where the
program is missing.

## Virtual groups

Some programs need a group of their own. The testers of Artemis's C GCC and C++ templates start the
program with `setsid` and stop it with `killpg(getpgid(pid))`, and SwiftPM starts each child with
`setpgid(0, 0)`. A process that moved leaves the group the kill targets.

So no process moves. Where a supervisor runs and can continue a call, the supervisor keeps a ledger
of virtual sessions and groups. The connect guard is that supervisor, or the report-only supervisor
beside the group lock. It answers `setsid` and `setpgid` from the ledger and never runs or continues
them. It answers `getpgid`, `getsid`, `getpgrp` and a `kill` to a group from the ledger when the
process is in it. A `kill` to a virtual group goes to the members only. Each one receives it through
a process descriptor whose start time the supervisor checked, so the signal stays inside the
sandboxed lineage.

The real group never changes, so the timeout still reaches every process. The page on what Phobos
does not protect against lists the differences a program can see. Membership follows the process
tree at the time of the question, and a process whose parent ended is no longer found.

## Why the cover is duplicated

The connect guard refuses the same two calls, and that cover belongs to the network layer. The
lock belongs to the timeout layer. A run with `--no-networksystem-restriction`, or the timeout
layer used on its own over a configuration, therefore keeps the group kill unescapable. Where
both filters speak the kernel takes the stricter action.

## What the layer does not bound

`timeout` bounds wall-clock time. Processor time is a separate limit, `cpu` in `[limits]`,
enforced by the kernel against the process through an rlimit, so a command that sleeps burns
the first and not the second.

## Further reading

- [`timeout` invocation](https://www.gnu.org/software/coreutils/manual/html_node/timeout-invocation.html):
  the GNU coreutils manual
- [`setsid(2)`](https://man7.org/linux/man-pages/man2/setsid.2.html) and
  [`setpgid(2)`](https://man7.org/linux/man-pages/man2/setpgid.2.html): the two calls the lock
  refuses
- [Seccomp](seccomp.md): the filter mechanism, and the guard that duplicates this cover
