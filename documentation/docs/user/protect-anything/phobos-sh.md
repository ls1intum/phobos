---
title: "phobos.sh"
sidebar_position: 1
description: "The entry point: how a run is assembled, which configurations apply, and what the exit status means."
---

:::tip[Simple Story]
One command in front of yours. Everything else follows from the policy.

`phobos.sh` reads the configuration, builds one description of the run, and then hands your
command down a chain of layers, each of which does its part and passes the rest on.
:::

`phobos.sh` is the entry point. Everything else in this section is a layer it assembles, and
each of those layers can be run on its own where you need to isolate a failure.

## Before the first run

A bare checkout cannot run Phobos, deliberately. Two things are missing from it:

- **The compiled programs.** `phobos-landlock-filesystem-and-networksystem`, the connect guard and the process-group lock
  are built from the source under `core/` and never committed. Where the connect guard, the
  Landlock program or the process-group lock is missing, the layer that needs it ends the run
  rather than running without it.
- **The base policy.** `phobos-policysystem.sh` finds it by globbing `Base*.cfg` beside itself, and a
  checkout keeps those files in `core/config/` rather than in `core/`. A run from a checkout is
  refused with `PHB-EPOLICY` instead of running unprotected.

The delivery vehicle is the run-phase image, which compiles both and puts the shipped policy
where the scripts look for it. Build it from the repository root:

```bash
.github/scripts/assemble-run-phase-context.sh build/run-phase-context
docker compose -f docker/run_phase/java/docker-compose.yaml up --build
```

Inside that image `PHOBOS_HOME` is `/var/tmp/opt/core`, and `phobos` on `PATH` is a symbolic
link to the same script.

## Running a command

```bash
${PHOBOS_HOME}/phobos.sh --config exercise.cfg -- ./gradlew test
```

The shipped base policy is applied without being named. `--config` is for the exercise's own
configuration, applied **on top of** that base, never for the base itself: naming a base file
there applies it a second time.

:::warning[A run given no `--config` is not a grading run]
Without one, Phobos takes its most restrictive shape. Every `[connect]`, `[bind]` and `[accept]`
rule the base granted is dropped, so the command reaches no network at all, loopback included,
and cannot bind or listen on any port. A Gradle build cannot reach its own daemon. The
filesystem keeps what the base granted, because a command whose own binary and libraries were
denied could not start at all. Give the exercise's own configuration for a real run.
:::

When no configuration names a value, the run is bounded by a default:

| Bound | Default | Applied as |
| --- | --- | --- |
| `timeout` | 600 seconds | wall-clock time |
| `mem_mb` | 8192 | `ulimit -v`, the virtual address space |
| `cpu` | 600 seconds | `ulimit -t`, CPU time across every thread |
| `nproc` | 256 | `ulimit -u`, counted per user |
| `nofile` | 1024 | `ulimit -n` |
| `fsize_mb` | 256 | `ulimit -f`, the size of any single file |

A configuration that names a larger value wins over the default, and one that names `0` switches
that limit off and wins over it too. The default is a fallback used only where no configuration names the limit. A configuration can name a lower value, and that value then applies. It is never a cap.

Both spellings of the command work. Everything after `--` is the command and its arguments; if
you leave `--` out, the first word that is not an option becomes the command and everything
after it becomes its arguments. An unknown option is refused rather than treated as the
command, so a mistyped flag fails with a message instead of ending up in `argv`.

## Which configurations apply, in which order

| Order | What | Where it comes from |
| --- | --- | --- |
| 1 | Base policy | every `Base*.cfg` beside `phobos-policysystem.sh`, in sorted order |
| 2 | Task configurations | each `--config` file, in the order given |
| 3 | Tail flags | `TailPhobos.cfg` beside `phobos-policysystem.sh`, or `--tail-flags-file` |

The model is additive in every dimension. Filesystem paths and network rules are unioned, and
for the timeout and each resource limit the largest value any configuration names wins, where a
zero switches that limit off and beats every finite value. A task configuration cannot narrow
below the base, which is exactly why it is trusted input.

:::warning[Ship exactly one `Base*.cfg` per runtime environment]
The base files are found by a glob and unioned. A `BasePhobos.cfg` left beside a
`BaseLanguage-java.cfg` gives a Java run the paths of every other language too, which is a
wider sandbox that looks like a working one. The discovery phase writes every alternative into
one directory on purpose; choosing between them is the packaging step.
:::

## Switching a layer off

Every restriction is applied by default. Each can be disabled on its own, which is how you find
out which layer a failure belongs to. The timeout, network and resource layers drop out of
the chain when disabled. The filesystem layer is the exception: it still runs the command and
counts denials, and `-nfr` only leaves Landlock out. Every one of them is recorded on standard
error, so a run with a layer off cannot look like an ordinary one in a log.

| Option | Short | Disables |
| --- | --- | --- |
| `--no-filesystem-restriction` | `-nfr` | the Landlock filesystem ruleset. The port rules are unaffected. |
| `--no-networksystem-restriction` | `-nnr` | the whole network restriction: the connect guard and the Landlock port rules |
| `--no-timeoutsystem-restriction` | `-ntr` | the timeout, and with it the process-group lock |
| `--no-resourcesystem-restriction` | `-nrr` | the resource limits |
| `--no-restriction` | `-nr` | every layer at once, even where a base policy is present |

`--no-restriction` runs the command raw, and it says so on standard error in a block that names
every layer it switched off. It is handled before any specification directory is created and
before the configurations are read, so a raw run leaves nothing behind. It is refused outright
beside `--config`, because giving a policy says a confined run was meant. That refusal is what
catches `-nr` typed where `-nrr` was meant: the two are one character apart, `-nrr` switches off
only the resource limits and `-nr` switches off the entire sandbox.

## The other options

| Option | What it is for |
| --- | --- |
| `--help` | Print the manual and end with status 0. Every script here, `phobos.sh` and each layer alike, has one: it names every flag the script parses with its default, both operating modes, the specification files it reads and the exit statuses it can end with. |
| `--debug` | Print on standard error what each layer does and runs, and have `phobos-landlock-filesystem-and-networksystem` and the connect guard report verbosely too. It prints the whole effective policy, so it is for diagnosis rather than for a production log. |
| `--resolver <ip[:port]>` | The Domain Name System (DNS) resolver the egress broker resolves an exact `[connect]` host name through. The default DNS port is added where no port is given. |
| `--spec-parent <path>` | Where the run's specification directory is made. The default is `/var/tmp`, and it must lie outside every write path. |
| `--landlock-bin`, `--connect-guard-bin`, `--pgroup-lock-bin` | Which program each layer uses. The default for each is the one beside the script. |
| `--timeout-bin`, `--haproxy-bin` | The timeout tool and the HAProxy the broker and the inbound filter run as. The default for each is that name on `PATH`. |
| `--tail-flags-file <path>` | The tail flags file, in place of `TailPhobos.cfg`. |

Every one of these is taken from the command line and never from the environment. A value left
in the environment cannot change which program applies the sandbox, and `--debug` in particular
can only be switched on by the flag.

## What the layers do, in order

```
phobos.sh -> phobos-timeoutsystem.sh -> timeout -> phobos-seccomp-timeoutsystem -> phobos-networksystem.sh
          -> phobos-seccomp-networksystem -> phobos-landlock-filesystem-and-networksystem --no-filesystem
          -> phobos-filesystem.sh -> phobos-resourcesystem.sh -> phobos-landlock-filesystem-and-networksystem -> your command
```

The network layer contributes two links: the connect guard, which it puts in front, and a
Landlock ruleset of its own carrying the port rules, which composes with the filesystem
layer's by intersection. That ruleset is applied on every run, even when the policy names no
port, because it is what closes bind. The network layer runs the rest of the chain as a child and
waits for it, rather than replacing itself with it, because it starts HAProxy processes and adds
`/etc/hosts` lines that must not outlive the run. When the command ends it stops the broker and
the inbound filter it started, and the lines it added are removed with the specification
directory.

`phobos.sh` builds the run's specification with `phobos-policysystem.sh`, then assembles that chain
from the flags. The resource layer is not a link of the chain: the filesystem layer starts it
as the last step before `phobos-landlock-filesystem-and-networksystem`, so the limits bind the command and none of the
helpers around it.

## Reading the result

Standard output carries the command's own output and nothing else. Every message from Phobos
goes to standard error, and the exit status is the contract to read.

| Status | Meaning |
| --- | --- |
| the command's own | Phobos did not stop the run |
| `128` plus a signal | a `SIGTERM`, `SIGHUP`, `SIGINT` or `SIGQUIT` sent to `phobos.sh` was passed on to the command, which died of it |
| `2` | a script was called the wrong way |
| `11` | `PHB-EPOLICY`: the policy is invalid or cannot be enforced as written |
| `14` | `PHB-ETIMEOUT`: the run passed its timeout and was stopped |
| `15` | `PHB-ERUNTIME`: something Phobos needs is missing or cannot be started |
| `125` | `phobos-landlock-filesystem-and-networksystem`, the connect guard or the group lock refused to set the sandbox up |
| `127` | the command itself could not be executed |

A run whose clean-up fails, because the specification directory or the run's `/etc/hosts` lines
cannot be removed, ends with `15` even where the command succeeded. A command that ignores the
signal goes on until its time limit, and `SIGKILL` cannot be passed on.

One more report carries no status of its own. Where the command's own standard error contained
lines that look like denials, the filesystem layer counts them and prints
`Sandbox denials: network=<n>, filesystem=<n>. (PHB-EDENY)`. It is a hint for a reader, never a
verdict: the count never changes the exit status.

## Further reading

- [Troubleshooting](../troubleshooting.md) — what each message means and what to do next
- [Policy Reference](/user/policy-reference/) — every section of a configuration file
- [Life of a sandboxed run](/contributor/life-of-a-sandboxed-run) — the same chain, from the
  inside
