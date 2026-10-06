---
title: "Life of a sandboxed run"
sidebar_position: 3
description: "From the command line to the command, stage by stage: what each layer builds, hands on and waits for."
---

:::tip[Simple Story]
One command goes in, and a chain of processes hands it along before it runs.

Each one does its own piece of work and then becomes, or starts, the next. The order is not
arbitrary: it is what keeps every limit on the command and off the helpers.
:::

## The chain

```
phobos.sh
  -> phobos-policysystem.sh                 (builds the specification, then returns)
  -> phobos-timeoutsystem.sh                (runs the rest under GNU timeout and waits)
       -> phobos-seccomp-timeoutsystem          (installs the seccomp filter, then execs)
       -> phobos-networksystem.sh           (starts the broker and the filter, runs the rest as a child, waits, then cleans up)
            -> phobos-seccomp-networksystem   (forks a supervisor, the child execs on)
            -> phobos-landlock-filesystem-and-networksystem        (--no-filesystem: the port rules only)
            -> phobos-filesystem.sh   (runs the command as a child and waits)
                 -> phobos-resourcesystem.sh  (sets the rlimits, then execs)
                 -> phobos-landlock-filesystem-and-networksystem      (the filesystem ruleset, then execs)
                 -> the command
```

The timeout, network and resource layers drop out of the chain when switched off, so no enable
flag travels with them. The filesystem layer is always in the chain: with `-nfr` it receives
`--no-landlock` and still runs the command as a child and counts denials.

## Stage 1: the command line

Every entry point, `phobos.sh` and each layer started on its own alike, first finds its own
directory in bash alone and sources `phobos-tools-common/phobos-environment.sh`.
`clean_startup_environment` then keeps only the absolute entries of `PATH`, `GCONV_PATH`,
`LOCPATH` and `NLSPATH`, unsets `CDPATH`, and unsets `TMPDIR`, `HOSTALIASES` and `TZDIR` where
they are not absolute. Nothing runs before that, no external program and no `cd`, because the
current directory can be the command's own tree. A `PATH` with no absolute entry ends the run
with `PHB-ERUNTIME`. Only then does the entry point source `phobos-common.sh`.

`phobos.sh` parses its own options and stops at the first word that is not one, or at `--`.
Everything from there is the command and its arguments. An unknown option is refused rather
than treated as the command.

Every override is taken from the command line and never from the environment. `--debug` in
particular resets on every source of the shared library, because bash imports each environment
variable as a shell variable of the same name and debugging must never be switchable from
outside.

`phobos.sh` handles `--no-restriction` (`-nr`) here, before any specification directory exists
and before it reads the configurations, so a raw run leaves nothing behind. It refuses a
`--config` given beside it, which catches `-nr` typed where `-nrr` was meant.

## Stage 2: the specification

`phobos.sh` creates a directory under `--spec-parent`, marks it as its own with a hidden
marker file, and calls `phobos-policysystem.sh` over it. That program is the only parser: it
discovers the base policy, parses every configuration, merges them and writes one file per
part.

| File | What it holds |
| --- | --- |
| `read.paths`, `execute.paths`, `write.paths`, `create.paths`, `delete.paths`, `ipc.paths`, `symlink.paths`, `refer.paths` | one path per line, per right |
| `net.rules` | one `host port [udp]` per line |
| `bind.rules` | one `* port [udp]` per line |
| `accept.rules` | one `public backend [source]` per line |
| `timeout.sec` | the canonical timeout, or empty |
| `limits.conf` | one `key=value` per resource limit |
| `tail.flags` | the tail flags, comments stripped |
| `net.guard.rules` | `net.rules` with the udp name rows expanded to addresses, written by the network layer for the guard |
| `hosts.record` | the hosts file whose lines the run added, so the clean-up can remove exactly those |

Every part `write_spec` writes gets its file even where it is empty, so each layer can read it
unconditionally. The last two files appear only when the network layer needs them.

Three checks happen here rather than in a layer, because a layer may be absent from the chain
and a rule must be judged either way: every network rule is judged for enforceability, every
`[accept]` rule is judged against the merged `[bind]` set, and the specification directory is
checked to lie outside every write path.

## Stage 3: the timeout

`phobos-timeoutsystem.sh` reads `timeout.sec`. Where it is empty, which happens only where a configuration wrote `0`, the layer hands the chain straight
on with `exec`, and no process-group lock is applied, since there is no group kill to escape.

Where a timeout is set the layer runs the rest under
`timeout --kill-after=5s <value>s phobos-seccomp-timeoutsystem -- ...` and **waits**. That makes it the
layer that outlives the run, so its trap is what removes the specification directory.

## Stage 4: the network

`phobos-networksystem.sh` does five things and then runs the rest of the chain as a child, so that it is still there to clean up when the command ends:

1. It resolves the host names of `udp` rules once, by running the guard in its resolve mode
   through `--resolver`, writes the guard a `net.guard.rules` with one row per address in place of
   each name, and maps the name to those real addresses in `/etc/hosts`.
2. It reads `net.rules` for stream rules whose host is a name, and starts the egress broker where
   it finds one, mapping each such name to a loopback placeholder in `/etc/hosts` first, except a
   name a `udp` rule already holds.
3. It starts the inbound filter where `accept.rules` is non-empty.
4. It builds the Landlock port arguments from `net.rules` and `bind.rules` and wraps the rest
   of the chain in `phobos-landlock-filesystem-and-networksystem --no-filesystem`, a network-only ruleset that composes with
   the filesystem layer's by intersection. Bind is always closed with `--close-bind`, and only a
   `[bind]` row opens a port.
5. It puts the connect guard in front of all of that.

The guard forks. The parent becomes the supervisor and is never restricted; the child installs
its seccomp filter, hands the notification descriptor up, and execs on. The port ruleset is
applied inside that child lineage, after the fork, so the supervisor that connects on the
command's behalf stays unrestricted. The supervisor runs every `listen` itself, and every datagram
`connect` and every send that names a destination, on a socket it created for the command.

When the command ends, the layer's `EXIT` trap stops the egress broker and the inbound filter it
started and removes the run's own lines from `/etc/hosts`, then passes the command's status
through unchanged.

## Stage 5: the filesystem, the resources, the command

`phobos-filesystem.sh` builds the `--rights=` arguments, appends the tail flags, and runs the
command as a **child** rather than replacing itself with it, so that it can watch the
command's standard error for denials. Between itself and `phobos-landlock-filesystem-and-networksystem` it starts
`phobos-resourcesystem.sh`, which sets the rlimits and execs on.

That ordering is the whole reason the resource layer is not a link of the outer chain: the
limits reach `phobos-landlock-filesystem-and-networksystem` and the command and nothing else. The layer shells, the standard
error pass-through, the denial counter and the connect guard's supervisor all run without them.

`phobos-landlock-filesystem-and-networksystem` then adds one `LANDLOCK_RULE_PATH_BENEATH` rule per path, enters the working
directory the tail flags named, sets `PR_SET_NO_NEW_PRIVS`, calls `landlock_restrict_self` and
execs the command.

## Signals, and who stays alive

Five properties hold the chain together, and each is easy to break:

- **The layers that wait ignore `SIGTERM`.** GNU `timeout` signals the whole process group, and
  the escalation to `SIGKILL` only fires while the timeout's own child is still alive. The
  layers below therefore stay up across `SIGTERM` and restore the default disposition for the
  command itself, in a subshell, just before running it. The `SIGKILL` then reaches a command
  that ignored the `SIGTERM`.
- **The layers pass a signal sent to `phobos.sh` on to the command.** A shell that waits for a
  child acts on a trapped signal only after the child ends, and a shell without a trap dies of
  the signal and leaves the command running. Every layer that waits therefore waits through
  `run_forwarding_signals` in `phobos-signals.sh`. It passes `SIGTERM`, `SIGHUP`, `SIGINT` and
  `SIGQUIT` on to its child, and the connect guard's supervisor passes them to its command. A
  command that dies of the signal ends the run with 128 plus its number, and the run cleans up.
  The helper returns whatever status its child ends with, so a handler that exits normally
  gives that status. It polls for the child's end with `sleep` and does not block in `wait`,
  because bash can wait for a child it has already reaped when a signal and the child's end
  coincide. Before it signals, it compares the child's start time from `/proc`, which makes
  a reused process number unlikely to be signalled. Where `/proc` cannot be read it checks the
  number alone. A command that ignores `SIGTERM` runs to its limit, and `SIGKILL` cannot be
  passed on.
- **The filesystem layer's wait for the denial counts is bounded**, and stays below the
  escalation, so `timeout` never escalates while the layer is still waiting.
- **The standard error pass-through and the denial counter ignore all four signals.** A
  terminal's Ctrl+C, quit or hangup reaches the whole process group, these helpers included. The
  filesystem layer makes them with `SIGTERM`, `SIGHUP`, `SIGINT` and `SIGQUIT` ignored and
  restores its own dispositions straight afterwards. They end when the command's standard error
  closes, so the output the command writes while it handles the signal reaches the terminal, and
  the counts survive. A hangup, quit or interrupt that arrives while the layer makes them is
  lost.
- **A timeout is a timeout only where the status and the clock agree.** GNU `timeout` passes a
  command's own status through, and a command killed by the out-of-memory killer ends with the
  same 137 as the escalation.

## Who removes the specification directory

Every layer that waits has an `EXIT` trap that removes it. The first to end does the work, and
the others find the directory gone. After a group `SIGKILL` only the timeout layer, which sits
outside the group, still removes it. `phobos.sh` itself ends with `exec`, so its own trap fires
only where the policy program refuses first.

The removal is conservative: it deletes only the files `write_spec` wrote, the scratch
subdirectory and the marker, then the directory itself. A directory that has gained anything
else stays, and the failure turns an otherwise successful run into `PHB-ERUNTIME` rather than
leaving a policy behind unnoticed. Stopping the HAProxy processes is the network layer's job, done
before it removes the directory: it keeps their process identifiers in shell variables and stops
them in its own `EXIT` trap.

## Further reading

- [Policy subsystem](subsystems/policy.md): stage 2 in detail
- [Network subsystem](subsystems/network.md): stage 4 in detail
- [Filesystem subsystem](subsystems/filesystem.md): stage 5 in detail
- [phobos.sh](/user/protect-anything/phobos-sh): the same chain, from the outside
