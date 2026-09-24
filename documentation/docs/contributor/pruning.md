---
title: "Pruning"
sidebar_position: 4
description: "The discovery phase: how it measures what a program needs, which way it errs, and what it writes."
---

:::tip[Simple Story]
Somebody takes one drawer away and asks the work to run again.

Nothing changed, so the drawer was never needed. The run broke, so it was. Doing that
repeatedly, from the top of the tree downwards, is the whole algorithm.
:::

The discovery phase decides what a policy permits. It runs once per runtime environment,
offline, and its output is the `BaseLanguage-<lang>.cfg` a protected run applies without being
named. Everything about the sandbox therefore rests on whether this phase measured the right
thing.

## The algorithm

`var/tmp/pruning/detect_minimal_fs.sh` takes a tree to prune and a script to run:

```bash
detect_minimal_fs.sh --target / --script /var/tmp/build.sh --lang java
```

It starts by making every child of the target writable and running the script once. A failure
there ends the run: nothing can be learned from a workload that does not work unrestricted.

Then it descends. For each directory, in order:

| Attempt | The directory becomes | Reading |
| --- | --- | --- |
| 1 | an empty writable temporary filesystem (`--tmpfs`) | the run still works, so it was never needed. Stop, and do not descend. |
| 2 | read-only (`--ro-bind`) | the run works read-only. Keep it so, and descend into it. |
| 3 | writable (`--bind`) | the run needs to write there. Keep it so, and descend into it. |
| — | it fails even writable | keep it writable and carry on; the cause lies elsewhere. |

The walk is top-down, so an unused subtree is dropped in one step rather than file by file, and
a directory that is hidden is never descended into.

Two compaction passes follow, and neither may fail the prune:

- **`demote_writable_parents`** turns a writable directory read-only where nothing beneath it
  is writable, so a parent does not carry a right only one child needed.
- **`collapse_readonly_parents`** removes the children of a read-only directory whose known
  children are all read-only, since the parent's entry already covers them.

## What the sandbox around a prune looks like

The measurement runs under Bubblewrap, which is the one place Phobos still uses it: a protected
run is enforced by Landlock and needs no namespace at all.

- The root is a temporary filesystem, and `/tmp` is a fresh one with nothing bound over it.
  Binding the host's `/tmp` there would let the sandbox read whatever any other process on the
  machine left in it.
- The environment is cleared and rebuilt. Only `PATH`, `HOME`, `LANG`, `LC_ALL` and `TERM`
  survive, and anything else a caller names with `--env`, so nothing arrives merely because it
  was set in the shell that started the prune.
- `--new-session` detaches the sandbox from the controlling terminal. Without it, and with no
  seccomp filter, a process inside could push characters back into that terminal with `TIOCSTI`
  and have them run outside.
- `--unshare-user` is deliberately absent. What is generated has to be the sandbox the
  measurement was made in; adding an option the prune never ran under would produce a policy
  nobody has tested.
- The invocation is an argument vector rather than a string for `bash -c`, so a directory whose
  name holds a quote, a dollar or a semicolon is a path rather than a command waiting for its
  turn.

## What counts as a successful run

An exit status is not a result. `build_outcome` reads the status together with the log, against
three patterns:

| Pattern | Effect |
| --- | --- |
| `IGNORABLE_FAILURE_PATTERNS` | a non-zero status whose log matches counts as success. Failing tests are a result, not a broken run. |
| `INFRA_FAILURE_PATTERNS` | a zero status whose log matches counts as failure. The toolchain itself broke. |
| `UNIGNORABLE_SUCCESS_PATTERNS` | a zero status whose log matches counts as failure. Gradle reports `NO-SOURCE` with status zero for a build that compiled nothing. |

All three are environment variables with defaults shaped for a Gradle build. Pruning anything
else means setting them, and getting them wrong is the failure mode this phase is most exposed
to: a run that fails for an unrelated reason is written into the allow-list as a dependency.

## Which way it errs

A pruning heuristic that treats an ambiguous outcome as "needed" produces a larger allow-list,
which is a weaker sandbox that still looks like it works. Three consequences are worth stating
in any change here:

- **A prune must not reach the network for anything it did not intend to.** A registry outage
  arriving as a sandbox regression is exactly this failure. Pin the versions a probe build
  resolves.
- **Prune with a cold cache.** A build that finds its dependencies, its wrapper distribution or
  its policy files already cached never touches the paths that fetch or unpack them, so the
  pruner hides those paths and the first run on a fresh machine fails.
- **Re-prune a layer when what it rests on changes**, and not otherwise: the base policy when
  the operating system of the image changes, a language policy when its toolchain changes, an
  exercise policy when the exercise changes.

## From path sets to a shipped policy

Each prune container works independently on its own language and writes into a shared mount;
nothing passes between containers except through that directory.

```bash
docker compose -f docker-compose.yaml up --build
```

`docker/prune_phase/orchestrate/orchestrate.py` then merges the per-workload artefacts. It
holds each path set to the record written beside it in the same run before it merges anything,
so a language that failed, one that produced nothing, and one whose artefacts disagree with
their record each stop the merge rather than shrinking it.

| Output | What it is |
| --- | --- |
| `BaseLanguage-<lang>.cfg` | the full binding set for one language |
| `BasePhobos.cfg` | the union across every language, for a runtime that cannot tell which is running |
| `TailPhobos.cfg` | the tail flags, which today is the working directory alone |

The Bubblewrap mount and namespace flags of the prune are dropped: they belong to the
measurement rather than to the policy.

:::warning[Ship exactly one `Base*.cfg` per runtime environment]
`phobos-policy.sh` applies every `Base*.cfg` it finds beside itself. A `BasePhobos.cfg` left
next to a `BaseLanguage-java.cfg` gives a Java run the paths of every other language too. The
orchestrator writes every alternative into one directory on purpose, because they are
alternatives rather than parts of one policy; choosing between them is the packaging step, and
`docker/run_phase/java/Dockerfile` does the choosing by naming one file.
:::

## The three files written for reading

They go to `debug/` and are never applied. They exist so that a policy can be judged rather
than only inspected:

| File | What it names |
| --- | --- |
| `BasePhobosIntersect.cfg` | what every language needed |
| `Base<Lang>Only.cfg` | what no other language needed, which is where a policy grows when one language's prune goes wrong |
| `Base<Lang>Common.cfg` | what every workload of that language needed with the same right |

A path two workloads needed with different rights is absent from the last of these, because the
intersection is taken over whole `mode path` lines.

## The asymmetry that catches people

The two phases do not deny in the same way. While pruning, a hidden directory is an empty,
**writable** temporary filesystem, because Landlock cannot make a path look empty. During a
protected run, a path the policy does not name is refused with `EACCES`.

A tool that only needs some writable scratch directory therefore passes its prune with that
directory hidden and is refused at run time. That is the first thing to check when a freshly
pruned policy fails a run that passed its prune.

## Review before you trust

Copying the result over the shipped `core/config/` is a deliberate step of its own. The
allow-list is only as tight as the reference workloads that produced it, and
`tests/policy-redundancy-probe.sh` reports which entries grant Landlock nothing an ancestor
already grants, which is worth reading while judging a fresh one.

## Further reading

- [Bubblewrap](technologies/bubblewrap.md) — the mechanism the measurement uses
- [What does Phobos not protect against](/user/phobos/what-does-phobos-not-protect-against) —
  what an empirical allow-list can and cannot promise
- [`CONTRIBUTING.md`](https://github.com/ls1intum/phobos/blob/main/CONTRIBUTING.md) — the rules
  for changing this phase
