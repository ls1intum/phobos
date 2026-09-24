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
  -> phobos-policy.sh                 (builds the specification, then returns)
  -> phobos-timeout.sh                (runs the rest under GNU timeout and waits)
       -> phobos-pgroup-lock          (installs the seccomp filter, then execs)
       -> phobos-network.sh           (starts the broker and the filter, then execs)
            -> phobos-connect-guard   (forks a supervisor, the child execs on)
            -> phobos-landlock        (--no-filesystem: the port rules only)
            -> phobos-filesystem.sh   (runs the command as a child and waits)
                 -> phobos-resources.sh  (sets the rlimits, then execs)
                 -> phobos-landlock      (the filesystem ruleset, then execs)
                 -> the command
```

A layer that is switched off is left out of the chain rather than entered and skipped, so no
enable flag travels with the run.

## Stage 1: the command line

`phobos.sh` parses its own options and stops at the first word that is not one, or at `--`.
Everything from there is the command and its arguments. An unknown option is refused rather
than treated as the command.

Every override is taken from the command line and never from the environment. `--debug` in
particular resets on every source of the shared library, because bash imports each environment
variable as a shell variable of the same name and debugging must never be switchable from
outside.

`--allow-unsandboxed` is handled here, before any specification directory exists and before the
configurations are read, so a raw run leaves nothing behind.

## Stage 2: the specification

`phobos.sh` creates a directory under `--spec-parent`, marks it as its own with a hidden
marker file, and calls `phobos-policy.sh` over it. That program is the only parser: it
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

Every part gets its file even where it is empty, so each layer can read it unconditionally.

Three checks happen here rather than in a layer, because a layer may be absent from the chain
and a rule must be judged either way: every network rule is judged for enforceability, every
`[accept]` rule is judged against the merged `[bind]` set, and the specification directory is
checked to lie outside every write path.

## Stage 3: the timeout

`phobos-timeout.sh` reads `timeout.sec`. Where it is empty the layer hands the chain straight
on with `exec`, and no process-group lock is applied, since there is no group kill to escape.

Where a timeout is set the layer runs the rest under
`timeout --kill-after=5s <value>s phobos-pgroup-lock -- ...` and **waits**. That makes it the
layer that outlives the run, so its trap is what removes the specification directory.

## Stage 4: the network

`phobos-network.sh` does four things and then replaces itself with the rest of the chain:

1. It reads `net.rules` for rules whose host is a name, and starts the egress broker where it
   finds one, mapping each exact name to a loopback placeholder in `/etc/hosts` first.
2. It starts the inbound filter where `accept.rules` is non-empty.
3. It builds the Landlock port arguments from `net.rules` and `bind.rules` and wraps the rest
   of the chain in `phobos-landlock --no-filesystem`, a network-only ruleset that composes with
   the filesystem layer's by intersection.
4. It puts the connect guard in front of all of that.

The guard forks. The parent becomes the supervisor and is never restricted; the child installs
its seccomp filter, hands the notification descriptor up, and execs on. The port ruleset is
applied inside that child lineage, after the fork, so the supervisor that connects on the
command's behalf stays unrestricted.

## Stage 5: the filesystem, the resources, the command

`phobos-filesystem.sh` builds the `--rights=` arguments, appends the tail flags, and runs the
command as a **child** rather than replacing itself with it, so that it can watch the
command's standard error for denials. Between itself and `phobos-landlock` it starts
`phobos-resources.sh`, which sets the rlimits and execs on.

That ordering is the whole reason the resource layer is not a link of the outer chain: the
limits reach `phobos-landlock` and the command and nothing else. The layer shells, the standard
error pass-through, the denial counter and the connect guard's supervisor all run without them.

`phobos-landlock` then adds one `LANDLOCK_RULE_PATH_BENEATH` rule per path, enters the working
directory the tail flags named, sets `PR_SET_NO_NEW_PRIVS`, calls `landlock_restrict_self` and
execs the command.

## Signals, and who stays alive

Three properties hold the chain together, and each is easy to break:

- **The layers that wait ignore `SIGTERM`.** GNU `timeout` signals the whole process group, and
  the escalation to `SIGKILL` only fires while the timeout's own child is still alive. The
  layers below therefore stay up across `SIGTERM` and restore the default disposition for the
  command itself, in a subshell, just before running it. The `SIGKILL` then reaches a command
  that ignored the `SIGTERM`.
- **The filesystem layer's wait for the denial counts is bounded**, and stays below the
  escalation, so `timeout` never escalates while the layer is still waiting.
- **A timeout is a timeout only where the status and the clock agree.** GNU `timeout` passes a
  command's own status through, and a command killed by the out-of-memory killer ends with the
  same 137 as the escalation.

## Who removes the specification directory

Whichever layer waits. With a timeout set, the timeout layer waits and its trap removes the
directory, including after it has just group-killed everything below. Without one, the
filesystem layer is the waiter and removes it. `phobos.sh` itself ends with `exec`, so its own
trap never fires.

The removal is conservative: it deletes only the files `write_spec` wrote, the scratch
subdirectory and the marker, then the directory itself. A directory that has gained anything
else stays, and the failure turns an otherwise successful run into `PHB-ERUNTIME` rather than
leaving a policy behind unnoticed. It stops the egress broker and the inbound filter first,
through the process-id files they recorded.

## Further reading

- [Policy subsystem](subsystems/policy.md) — stage 2 in detail
- [Network subsystem](subsystems/network.md) — stage 4 in detail
- [Filesystem subsystem](subsystems/filesystem.md) — stage 5 in detail
- [phobos.sh](/user/protect-anything/phobos-sh) — the same chain, from the outside
