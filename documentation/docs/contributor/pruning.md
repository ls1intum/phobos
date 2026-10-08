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

Two pruners exist side by side. [The layer pruner](#the-layer-pruner) prunes Java. It runs the
reference exercise through the grading layers themselves and grants only what a recorded refusal
proves. Python still uses the Bubblewrap walk that the next sections describe.

## The Bubblewrap algorithm

`var/tmp/pruning/detect_minimal_fs.sh` takes a tree to prune and a script to run. The entry
point is `run_minimal_fs_all.sh <lang>`, which copies each reference exercise to a scratch
directory, sets `HOST_WORKDIR`, calls `detect_minimal_fs.sh` on it and turns `final_bindings.txt`
into per-exercise path sets with `emit_artifacts.py`. Each language's `make_lang_sets.py` then
writes the union and the intersection. Called on its own, `detect_minimal_fs.sh` needs
`HOST_WORKDIR` when the script is a path inside the sandbox:

```bash
HOST_WORKDIR=/srv/exercise detect_minimal_fs.sh --target / --script /var/tmp/build.sh --lang java
```

It starts by making every child of the target writable and running the script once. A failure
there ends the run: nothing can be learned from a workload that does not work unrestricted.

Then it descends. For each directory, in order:

| Attempt | The directory becomes | Reading |
| --- | --- | --- |
| 1 | an empty writable temporary filesystem (`--tmpfs`) | the run still works, so it was never needed. Stop, and do not descend. |
| 2 | read-only (`--ro-bind`) | the run works read-only. Keep it so, and descend into it. |
| 3 | writable (`--bind`) | the run needs to write there. Keep it so, and descend into it. |
| after 3 | it fails even writable | keep it writable and carry on; the cause lies elsewhere. |

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
  survive, plus `BUILD_HOME` and `BUILD_OPTS` where given, and anything else a caller names with `--env`, so nothing arrives merely because it
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

All three are environment variables. The defaults of the first and third are shaped for a Gradle
build and the default of the second for a Python one. Pruning anything else means setting them.
Getting them wrong is the failure mode this phase is most exposed to: a run that fails for an unrelated reason is written into the allow-list as a dependency.

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

Each prune container works independently on its own language and writes into the shared
`var/tmp/path_sets` directory; nothing passes between containers except through that directory.

```bash
docker compose -f docker-compose.yaml up --build
```

The Java container runs on an image built from the run-phase image `phobos-run-phase-java`, so
build that first (`docker/run_phase/java/docker-compose.yaml` says how). It writes a complete
`java_<exercise>.cfg` and its record per exercise. The Python container writes a
`python_<exercise>.paths` path set and its record.

`docker/prune_phase/orchestrate/orchestrate.py` then merges the per-workload artefacts. It
holds each artefact to the record written beside it in the same run (a `.cfg` to the SHA-256 its
record carries) before it merges anything, so a language that failed, one that produced
nothing, and one whose artefacts disagree with their record each stop the merge rather than
shrinking it. It stops the merge when an exercise aborted or when a language has artefacts
of both kinds.

| Output | What it is |
| --- | --- |
| `BaseLanguage-<lang>.cfg` | the union of the language's exercises, without limits |
| `exercises/java_<exercise>.cfg` | for each Java exercise, its limits and whatever the base lacks. The base is the union of every exercise, so in practice only the limits. Passed with `--config`. |
| `BasePhobos.cfg` | the union across every language, for a runtime that cannot tell which is running |
| `TailPhobos.cfg` | the tail flags, which today is the working directory alone |

Everything goes under `var/tmp/opt/core/config` of the shared mount. A last container,
`verify_java`, runs every Java exercise once more under exactly that pair, the base and the
exercise file, as grading applies them, and writes its records to `path_sets/verify/`.

The Bubblewrap mount and namespace flags of the prune are dropped: they belong to the
measurement rather than to the policy.

:::warning[Ship exactly one `Base*.cfg` per runtime environment]
`phobos-policysystem.sh` applies every `Base*.cfg` it finds beside itself. A `BasePhobos.cfg` left
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

For the Bubblewrap prune, the two phases do not deny in the same way. While pruning, a hidden directory is an empty,
**writable** temporary filesystem, because Landlock cannot make a path look empty. During a
protected run, a path the policy does not name is refused with `EACCES`.

A tool that only needs some writable scratch directory therefore passes its prune with that
directory hidden and is refused at run time. That is the first thing to check when a freshly
pruned policy fails a run that passed its prune. The layer pruner has no such difference, because
it measures under the grading layers.

## Review before you trust

Copying the result over the shipped `core/config/` is a deliberate step of its own. The
allow-list is only as tight as the reference workloads that produced it, and
`tests/policy-redundancy-probe.sh` reports which entries grant Landlock nothing an ancestor
already grants, which is worth reading while judging a fresh one.

## The layer pruner

The layer pruner replaces that difference with the grading layers themselves. It runs the
reference exercise through the shipped `phobos.sh` and starts from a policy that grants nothing.
It records every call the layers refuse under `strace`, which needs ptrace and no privilege. It
then grants exactly what each recorded refusal proves: a file the run read, a directory it
created in, a loopback server it talked to.

Four steps follow the first grants:

1. It removes every grant that two runs show the build did not need.
2. It measures the limits and adds margins.
3. It verifies the result with every layer on.
4. It proves the forbidden direction with canary files, an unnamed host and port, and a probe
   that exceeds each limit it can reach.

The record lists any limit the pruner could not reach, and why. Each filesystem and limit check
first runs without Phobos, so only the sandbox's refusal counts.

A run that fails without a refusal the pruner can attribute never becomes a grant. The pruner
aborts that exercise instead. Before every layered run it removes whatever earlier runs added
outside the working directory, so each run starts as a fresh grading container does. That deletes
files, so the pruner runs only in the prune image, which sets `PHOBOS_PRUNE_CONTAINER=1`.

The code is in `var/tmp/helpers/layer_prune/`:

- `strace_parse.py` turns the log into the calls made inside the command's Landlock domain.
- `record.py` holds the shared records.
- `attribute.py` assigns each refusal to a layer and to the configuration sections that grant it.
- `control.py` replays each candidate outside every Landlock domain, so a refusal that Landlock
  did not cause never becomes a grant.
- `search.py` grows and minimises the policy.
- `generalise.py` decides when a file becomes its directory.
- `cfgfile.py` writes the result as a policy the parser accepts.

The image, `docker/prune_phase/layers/Dockerfile`, adds `strace` and `python3` to the run-phase
image. Its only base, `BasePrune.cfg`, grants nothing, so every grant in a pruned policy has a
refusal behind it.

Compose runs the layer pruner for Java. Build the prune image on a run-phase image and prune every
exercise under one key by hand, in an ordinary container:

```bash
docker build --build-arg RUN_PHASE_IMAGE=phobos-run-phase:ci -f docker/prune_phase/layers/Dockerfile -t phobos-prune-layers .
docker run --rm --network none \
  -v "$PWD/var/tmp/testing-dir:/srv/phobos-prune-exercises:ro" -v "$PWD/var/tmp/helpers:/var/tmp/helpers:ro" \
  -v "$PWD/var/tmp/path_sets:/var/tmp/path_sets" phobos-prune-layers \
  python3 /var/tmp/helpers/layer_prune/main.py <key>
```

Each exercise gets `<key>_<exercise>.cfg`, a complete Phobos configuration, and
`<key>_<exercise>.json`. The record lists every run, every denial with the grant it produced or
the reason it produced none, every widening and every containment check. An exercise that aborts
gets `<key>_<exercise>.aborted.json` and no configuration. The policy stays only as good as the
reference: the grading layers refuse a code path that the reference never took.

Four rules for an exercise are worth knowing:

- A Gradle build must run without a daemon, because the timeout's group lock refuses the `setsid`
  that a daemon needs.
- The pruner derives the memory limit only for an exercise whose `prune.json` declares
  `"heap_pinned": true`.
- An exercise that needs an external host declares it in `prune.json`
  (`"declared_hosts": ["api.example.org:443"]`). The opt-in Compose service `prune_java_egress`
  prunes it under the key `java-egress`, and that is the only layer-pruner service with a network.
  The service keeps a declared rule only when the build needs it, drops the others, and aborts on
  any host that nobody declared.
- The pruner reports a write on a name that changes from run to run, such as a process number
  under `/proc`, and never grants it. It never widens `[execute]` to a directory that holds a
  write-class right as well.

## The recording pruner

The recording pruner lives in `var/tmp/helpers/layer_record/`. It records the reference program of
an exercise while a person uses it, with the terminal passed through, so the paths the program
touches and the endpoints it reaches become known without a scripted workload. Only
`phobos-record` in the prune image starts it. Nothing under `core/` names it, and the run-phase
image does not hold it. While it records, the program runs with no sandbox at all, so use it for
the instructor's reference program and never for an untrusted one.

`phobos-record record` writes a session under `/var/tmp/recordings/<name>`.
`phobos-record check` replays that session under `phobos.sh` with the recording's policy, in a new
container, and fails on every refusal of something the recording did. The check refuses to run in
the container that recorded, or in one whose starting state differs, unless you give
`--same-container`.

Five modules sit around them:

- `guard.py` refuses to start where grading could be meant.
- `snapshot.py` lists a container's starting state.
- `pty_script.py` types scripted terminal sessions.
- `names.py` recovers the host names a session sent or received.
- `needs.py` maps each call to the sections of a policy.

The recorder does not turn a recording into a policy yet.

## Further reading

- [Bubblewrap](technologies/bubblewrap.md): the mechanism the measurement uses
- [What does Phobos not protect against](/user/phobos/what-does-phobos-not-protect-against):
  what an empirical allow-list can and cannot promise
- [`CONTRIBUTING.md`](https://github.com/ls1intum/phobos/blob/main/CONTRIBUTING.md): the rules
  for changing this phase
