---
title: "Pruning"
sidebar_position: 4
description: "The discovery phase: how it measures what a program needs, which way it errs, and what it writes."
---

:::tip[Simple Story]
Somebody locks every drawer and lets the work run.

Each time the work reaches for a drawer it cannot open, that is written down, and exactly that
drawer is unlocked. Then the work runs again with the drawers it did not touch locked once more.
:::

The discovery phase decides what a policy permits. It runs once per runtime environment,
offline, and its output is the `BaseLanguage-<lang>.cfg` a protected run applies without being
named. Everything about the sandbox therefore rests on whether this phase measured the right
thing.

Two programs do the measuring, and neither uses Bubblewrap any more. [The layer
pruner](#the-layer-pruner) prunes every language: it runs the reference exercise through the
grading layers themselves and grants only what a recorded refusal proves, so pruning and
grading deny in the same way. [The recording pruner](#the-recording-pruner) records a person
using the reference program and checks a policy against that session.

## What counts as a successful run

An exit status is not a result. `verdict.py` reads the status together with the log and the
JUnit reports the tests wrote, and two runs agree only when the same tests ran with the same
outcomes:

- Gradle reports `NO-SOURCE` with status zero for a build that compiled nothing, and Maven
  skips its tests with status zero (`No tests to run.`, `Tests are skipped.`). Pytest says
  `no tests ran` and ends with status 5. All of these count as a run that ran no tests.
- A line that shows the build's own machinery broke, such as a Python traceback before any test
  or `ModuleNotFoundError`, counts as an infrastructure failure, whatever the status.
- Maven's line for a pinned artefact the offline repository lacks aborts the unsandboxed
  baseline.

Getting this wrong is the failure mode this phase is most exposed to: a run that fails for an
unrelated reason must never be written into the allow-list as a dependency.

## Which way it errs

A pruning heuristic that treats an ambiguous outcome as "needed" produces a larger allow-list,
which is a weaker sandbox that still looks like it works. Three consequences are worth stating
in any change here:

- **A prune must not reach the network for anything it did not intend to.** A registry
  outage arriving as a sandbox regression is exactly this failure. Pin the versions a probe
  build resolves.
- **Prune with a cold cache.** A build that finds its dependencies, its wrapper distribution or
  its policy files already cached never touches the paths that fetch or unpack them. The pruner
  then never learns that they are needed, and the first run on a fresh machine fails.
- **Re-prune a layer when what it rests on changes**, and not otherwise. Re-prune the base
  policy when the operating system of the image changes, a language policy when its toolchain
  changes, and an exercise policy when the exercise changes.

## The layer pruner

The layer pruner prunes on the grading layers themselves. It runs the
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
image of the language being pruned (`phobos-run-phase-java` or `phobos-run-phase-python`). Its only base, `BasePrune.cfg`, grants nothing, so every grant in a pruned policy has a
refusal behind it.

Compose runs the layer pruner for every language. Build the prune image on a run-phase image and prune every
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

### The Maven prune

The Maven reference exercise, `var/tmp/testing-dir/java-maven/maven-reference/`, is Artemis's
Maven test template with Ares 2, built offline. It is pruned under its own key, `java-maven`, in
the same image as the Gradle one, by the Compose service `prune_java_maven`. The service
`verify_java_maven` verifies it.

The image holds the dependencies Maven resolves, pre-loaded and held to
`docker/run_phase/java/maven-repository.sha256`, and `tests/integration/layer_prune_maven.sh`
re-hashes every file the manifest lists before it prunes. Maven offline stops at the first
dependency file it cannot read, so granting that repository file by file would take one prune
round per file. Inside a fine-grained root such as `/root` a grant is otherwise always file by
file, apart from names that change from run to run. This one tree is the exception, because the
image build fixed its files by checksum:

- The exercise's `prune.json` declares it, `"pinned_read_roots": [{"path":
  "/root/.m2/repository", "manifest": "/srv/phobos-manifest/maven-repository.sha256"}]`, and the
  declaration is checked strictly: an absolute, normalised path beneath a fine-grained root, a
  manifest directly in `/srv/phobos-manifest`, and no field that could name a right.
- The pruner re-hashes every listed file by the rule of `pin-repository.sh` before any run and
  refuses the exercise on a mismatch.
- A `[read]` of anything beneath the tree is then granted as that one directory, `[read]` only,
  never widened to `/root/.m2` or `/root`, with a comment in the policy saying why.
- Every other grant under `/root` is a single file, writes stay file by file, and no write-class
  right is granted under `/root/.m2`.

This errs wider than the reference for that tree alone: a graded build can read any file in it.
The manifest lists what the pre-load added, 59 files; the rest of the tree comes with the
digest-pinned base image, and the record counts it. The result is
`BaseLanguage-java-maven.cfg` and `exercises/java-maven_maven-reference.cfg`, a base to review and
adopt in a pull request of its own that lists every widening.

The build writes scratch files with random names in `/tmp` (Ares, Surefire), which the pruner never
grants from a refusal. The exercise's `prune.json` therefore names a seed, `"seed": "java.cfg"`,
a file beside the prune image's Dockerfile (`docker/prune_phase/layers/seeds/java.cfg`) that
starts the first policy with `[read]`, `[write]`, `[create]` and `[delete]` on `/tmp`. The
minimisation drops a row the build does not need, and one comment above the path names the seeded
rows that stayed. Language-specific rows live only in such a file, never in the pruner or in
`core/`. The Gradle reference exercise names the same seed, but no Gradle prune has run on the
layers since the move to the Java Development Kit (JDK) 25, so that is unobserved.

Without the Compose setup, the manual workflow `prune-maven.yml` builds both images on amd64 and
arm64 and runs `tests/integration/layer_prune_maven.sh` in an ordinary container. That prunes,
merges and verifies the exercise. It shows four wrong reasons aborting: no tests, a version the
repository lacks, a manifest that does not match, and no seed named. The policy, its record and
the merged base stay as workflow artefacts.

### The KVM run, a second observer on x86

The container kernels the prune runs on offer Landlock version 8 at most. They never refuse what
versions 9 and 10 add, in particular a UDP bind to an explicit port, and they give no access to
Landlock's own audit records. The manual workflow `prune-kvm.yml` therefore takes what the default
prune wrote. It runs the same layers, in the root file system of the same prune image, on a
pinned Linux 7.2 kernel in a QEMU guest under KVM, where the pruner owns the kernel. It runs on
x86 runners only, in three jobs: the default prune in an ordinary container, the audit observer
in the guest, and the orchestrator over both.

The observer, `main.py --kernel-observer audit`, writes nothing a prune writes. It proves first,
inside the guest, that the kernel offers Landlock version 10 and that one deliberate refusal
produces exactly one record it can read. Otherwise it ends as indeterminate (status 3), never as
a pass. Then, per exercise, it compares each Landlock refusal strace attributed with the kernel's
record, and verifies the policy on this kernel. A mismatch fails the job and means the mapping from
call to right is wrong for that call.

The one thing it can add is a `[bind] allow <port> udp` row for a UDP bind the kernel's record
names as refused. The row goes in `<key>_<exercise>.abi10.cfg`, beside
`<key>_<exercise>.abi10.json`, which names the SHA-256 of the `.cfg` it verified and of the
sidecar. The orchestrator refuses a record
or a sidecar that is not the one it names and writes the rows to `Abi10-<lang>.cfg`, never into
the base. The enforcer refuses a UDP rule that names a port on a kernel below Landlock version 10,
so a base that held one would stop every run of the language there. A host known to have version
10 passes the file with `--config`.

A base generated without such a run is complete up to Landlock version 9 and, on a version 10
kernel, refuses an explicit UDP bind the exercise needs, so it fails closed. Any other difference
between the two kernels fails the exercise. All of this is unproven until the workflow has run to
the end. The fixture's audit records under `tests/python/fixtures/audit/` are written in the
kernel's documented layout, and the first run replaces them with the raw lines it uploads.

## From exercise policies to a shipped policy

Each prune container works independently on its own language and writes into the shared
`var/tmp/path_sets` directory; nothing passes between containers except through that directory.
Every language is pruned by the layer pruner, on an image built from that language's run-phase
image, so build the run-phase images first (`docker/run_phase/<language>/docker-compose.yaml`
says how):

```bash
docker compose -f docker-compose.yaml up --build
```

Each container writes a complete `<lang>_<exercise>.cfg` and its record per exercise.
`docker/prune_phase/orchestrate/orchestrate.py` then merges them. It holds each `.cfg` to the
SHA-256 its record carries before it merges anything. A language that failed, one that
produced nothing, and one whose `.cfg` its record does not vouch for each stop the merge rather
than shrinking it. An aborted exercise stops the merge as well.

| Output | What it is |
| --- | --- |
| `BaseLanguage-<lang>.cfg` | the union of the language's exercises, without limits |
| `exercises/<lang>_<exercise>.cfg` | for each exercise, its limits and whatever the base lacks. The base is the union of every exercise, so in practice only the limits. Passed with `--config`. |
| `BasePhobos.cfg` | the union across every language, for a runtime that cannot tell which is running |
| `TailPhobos.cfg` | the tail flags, which today is the working directory alone |
| `Abi10-<lang>.cfg` and `exercises/<lang>_<exercise>.abi10.cfg` | the rows only a kernel with Landlock version 10 can prove, from [the KVM run](#the-kvm-run-a-second-observer-on-x86). Never part of the base. |

Everything goes under `var/tmp/opt/core/config` of the shared mount. A last container per
language, `verify_java`, `verify_java_maven` and `verify_python`, runs every exercise once more
under exactly that pair, the base and the exercise file, as grading applies them, and writes its
records to `path_sets/verify/`.

:::warning[Ship exactly one `Base*.cfg` per runtime environment]
`phobos-policysystem.sh` applies every `Base*.cfg` it finds beside itself. A `BasePhobos.cfg` left
next to a `BaseLanguage-java.cfg` gives a Java run the paths of every other language too. The
orchestrator writes every alternative into one directory on purpose, because they are
alternatives rather than parts of one policy. Choosing between them is the packaging step, and
`docker/run_phase/java/Dockerfile` does the choosing by naming one file.
:::

## The three files written for reading

They go to `debug/` and are never applied. They exist so that a policy can be judged rather
than only inspected:

| File | What it names |
| --- | --- |
| `BasePhobosIntersect.cfg` | what every language needed |
| `Base<Lang>Only.cfg` | what no other language needed, which is where a policy grows when one language's prune goes wrong |
| `Base<Lang>Common.cfg` | what every exercise of that language needed: the sections every exercise granted a path, raised as the base is |

## Review before you trust

Copying the result over the shipped `core/config/` is a deliberate step of its own. The
allow-list is only as tight as the reference exercises that produced it, and
`tests/policy-redundancy-probe.sh` reports which entries grant Landlock nothing an ancestor
already grants, which is worth reading while judging a fresh one. A scratch directory that a
tool merely needs writable passes the prune and is granted at grading time as well. The pruner
measures under the grading layers, so the two phases do not differ.

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

- [What does Phobos not protect against](/user/phobos/what-does-phobos-not-protect-against):
  what an empirical allow-list can and cannot promise
- [`CONTRIBUTING.md`](https://github.com/ls1intum/phobos/blob/main/CONTRIBUTING.md): the rules
  for changing this phase
