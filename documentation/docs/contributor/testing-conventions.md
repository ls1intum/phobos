---
title: "Testing conventions"
sidebar_position: 2
description: "What the four families of suite prove, how each reports, and why a skip is not a pass."
---

:::tip[Simple Story]
A sandbox suite can go green two ways: because the boundary held, or because the check never
ran.

Every suite here counts its skips separately and says so, because a skip reads as a pass in a
workflow summary.
:::

There is no build system. The shell runs as it is and the C is compiled inside the image, so
the suites under `tests/` are the checks.

## One harness, six families

Every suite sources `tests/harness.sh`, which owns `ok`, `bad`, `skip`, `check`, the three
counters and `finish`. A suite keeps everything else of its own: its shell options, its
fixtures and its cleanup trap. Each reports its own passed, failed and skipped counts and exits
non-zero on a failure.

| Family | Where | What it needs | Run by |
| --- | --- | --- | --- |
| Integration suites | `tests/integration/*.sh` | a shell, `gcc-14`, `haproxy`, `openssl` | the `Shell suites` job of `test.yml`, in continuous integration (CI) |
| Shell unit suites | `tests/unit/<core component>/*.sh` | a shell | the `Shell suites` job of `test.yml` |
| Python suites | `tests/python/` | pytest | the `Python helpers` job of `test.yml` |
| C unit suites | `tests/unit/phobos-landlock-filesystem-and-networksystem/`, `tests/unit/phobos-seccomp-networksystem/`, `tests/unit/phobos-seccomp-filesystem/` | `gcc-14`, no kernel feature | the `unit` job of `build.yml` |
| Acceptance suites | `tests/integration/landlock-filesystem-and-networksystem-acceptance/` | the run-phase image, an ordinary container | the groups of the `run-phase` job of `build.yml`, on amd64 and arm64 |
| Protection matrix | `tests/integration/protection-matrix/` | the run-phase image, an ordinary container | the groups of the `run-phase` job of `build.yml`, on amd64 and arm64 |

The `run-phase` job is a matrix of parallel groups on each architecture: `acceptance`, `matrix-a`,
`matrix-b`, `recorder-and-egress` and `pruner`. A group is a slice of the suites, so one slow
suite no longer makes every run wait for the sum of all of them. The Python run-phase image has
its own job with the groups `suites-a`, `suites-b`, `pruner-a` and `egress`. It holds that image to
every suite that needs no Java, while the acceptance suites that compile Java probes or run Maven
stay with the Java image. On the free plan GitHub runs at most 20 jobs at once, so every new group
counts against that limit.

Some integration suites run elsewhere. They need the prune image that the `run-phase` job of
`build.yml` builds on the run-phase image, so the `pruner` and `recorder-and-egress` groups run
them, in an ordinary container:

- `layer_prune_observer.sh`
- `layer_prune.sh`, the whole layer pruner on its fixture exercise, in both directions
- `layer_prune_egress.sh`, the declared hosts
- `record_host.sh`, which starts the recording pruner's own suites: `record_safety.sh`,
  `record_interactive.sh`, `record_replay.sh` and `record_generate.sh`
- `record_networked.sh`, which runs the recorder against a stand-in server on a Docker network
  with no route out and replays the generated host name rule through the egress broker

The Python suites cover the modules of both pruners too, from a recorded `strace` log and
captured packets under `tests/python/fixtures/`.

Each shell suite is a CI step of its own, so one run names every suite that broke rather than
the first alone. `tests/README.md` is the table of every suite, what it proves and what makes it
skip. `harness_self_test.sh` runs first as a step of its own. A step named "Every suite is started
by a workflow" fails when a `*.sh` file under `tests/` is named in no workflow, apart from
`harness.sh`, `lib.sh`, `run-all.sh` and `policy-redundancy-probe.sh`. It matches on the file
name, so a suite that nobody wired in cannot sit green by never running. A second step checks
that the entry points of `core/` and `var/tmp/pruning/` are executable. Some integration suites
skip without `haproxy` or `openssl`, and `seccomp_networksystem.sh` skips without the kernel's
seccomp user notification.

## A skipped check is not a passing one

Where a suite can skip, its row in `tests/README.md` says what makes it skip and what turns
that skip into a failure. The example that carries the principle:

- `timeout_escalation.sh` skips where GNU `timeout` or a compiler is absent. A probe that does
  not compile is a failure rather than a skip, because a probe that fails to build proves
  nothing about the escalation it was meant to measure.

## The unit suites interpose rather than run

The C unit suites compile the code under test and interpose every system call it makes, so
they need no kernel feature and no privilege. That is what lets them exercise a Landlock
version the runner does not have, and a failure path the kernel would never produce to order.

Two of them carry a coverage gate:

| Suite | Gate |
| --- | --- |
| `tests/unit/phobos-seccomp-networksystem/seccomp_networksystem_run.sh` | every line, with `--coverage` |
| `tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh` | every line of the report-only supervisor's sources, with `--coverage`, and its quoting held to bash's own over a corpus of names |
| `tests/unit/phobos-landlock-filesystem-and-networksystem/run.sh` | none. `mutation.sh` in the same folder reports a mutation score for it instead, because the coverage runtime disturbs the calls the suite interposes |

The mutation score answers a different question from coverage: coverage says a line ran, and
mutation shows whether a test notices when a line is wrong. The `mutation` job of
`build.yml` breaks the Landlock program's sources one small change at a time, runs the suite for
each and reports the share it catches. It needs clang 20 and mull in an Ubuntu 26.04 container,
reports a score without gating on it, and fails where it reaches no score. It runs on every
change and weekly.

## The acceptance suites measure the real sandbox

They run inside the run-phase image, in an **ordinary** container: no `--privileged`, no
`--cap-add`, no `--security-opt`, and `--network none`. A suite that needed any of those would
be measuring a different sandbox from the one a command gets, which is why that constraint is
part of the convention rather than part of the setup.

Nine suites cover, in order: the five guarantees of the shipped policy, inheritance by a
second process and a non-root run, rights tightened and widened across four phases, the policy
the image ships running a real build, a raw `connect()` refused by a Landlock port rule, a raw
bind refused by a Landlock bind-port rule, Landlock scoping against signals and abstract sockets,
the connect guard inside the image, and the network layer leaving nothing behind. That last
suite checks that no HAProxy remains and that `/etc/hosts` is byte for byte as it was, even
after a `SIGKILL`ed timeout and two overlapping runs.
The job runs on both architectures, and the image build checks with `readelf` that the three
compiled programs are position independent with full RELRO.

## The protection matrix

The acceptance suites measure the shipped policy. The matrix under
`tests/integration/protection-matrix/` holds `phobos.sh` itself to its promises, layer by layer
and combined. It has eleven suites (`filesystem`, `network`, `timeout`, `resources`,
`combinations`, `cli`, `lifecycle`, `policy-syntax`, `network-edge`, `filesystem-edge` and
`resources-edge`), each a step of the `run-phase` job in an ordinary container with
`--network none --memory 3g --pids-limit 1024`. The cgroup caps are not privileges. `lib.sh`,
`probe.c`, `edge.c`, `stubdns.c` and `run-all.sh` are the shared parts.

The conventions are these:

- Every denial has three partners: an unprotected control, a refusal through `phobos.sh`, and a
  pass with only its own layer switched off. A control that fails turns the check into a skip
  that says there is no evidence.
- Every denial has a permitted neighbour, so a sandbox that refuses everything cannot pass.
- `probe.c` prints `START` and then `OP <name> ret=<n> errno=<NAME>` for each call, so a suite
  reads what the kernel answered and not an exit code.
- `gap_case` pins a documented limit as it is today and turns red on a change in either
  direction. `known_defect` skips while a defect holds and fails the moment it is fixed. A skip
  is never a pass.
- A refusal that is new belongs in the matrix too: it pins old behaviour as an ordinary accept
  or a `gap_case`, so a parser that starts to refuse fails there first.

Run it with `run-all.sh [suite...]` in a disposable container only, with `--network none`: the
suites replace the image's base policy for their duration and end helper processes with `pkill`.

## Both directions, always

A change to the sandbox needs two tests, not one:

- the permitted case still works, which says the sandbox is usable;
- the nearest forbidden neighbour is still denied, which says the boundary held.

Either alone passes for the wrong reason. `tests/integration/filesystem_policy.sh` is the worked example:
it pins that a nested entry narrower than its ancestor is refused **and** that a merely
different one is allowed, because a change that tightened the first would silently break the
second.

## The probes are not suites

Two scripts under `tests/` report for themselves and gate no pull request:

- `runner-capability-probe.sh` answers what a machine can do, and is run by
  `runner-capabilities.yml` on request. Each assert mode answers 0 for yes, 1 for no and 3 for
  cannot tell. `--assert-landlock` asks whether Landlock enforces. `--assert-kvm` asks whether a guest kernel boots under
  KVM, and `runner-capabilities.yml` asks it on each hosted runner image. `--assert-ptrace` asks whether a tracer without privileges sees
  a traced Landlock refusal inside an ordinary container, which the layer pruner's observer
  relies on. `runner-capabilities.yml` fails only where a probe cannot tell.
- `policy-redundancy-probe.sh` names the entries of a policy that grant Landlock nothing an
  ancestor already grants. Those entries are not dead code, so it reports rather than failing.
  Run it where the policy is applied, since it resolves symbolic links.

## The environment variables the suites read

| Variable | Read by | Meaning |
| --- | --- | --- |
| `COMPILER` | the unit runners | the compiler to build the C under test with, `gcc-14` by default |
| `COVERAGE_TOOL` | the unit runners | the gcov matching that compiler, `gcov-14` by default |
| `PHOBOS_HOME` | the acceptance suites | where Phobos is installed in the image, `/var/tmp/opt/core` by default |
| `PROBE_CONTAINER_IMAGE` | `runner-capability-probe.sh` | the image the container half of the probe runs in |
| `LAYER_PRUNE_HELPERS` | `layer_prune_observer.sh` | the directory that holds the layer pruner's Python package, `/var/tmp/helpers` by default |
| `PRUNE_LOG_DIR`, `PRUNE_TARGET`, `TESTING_DIR`, `PHOBOS_KEEP_LOG` | the prune suites and the pruner | where a prune writes its logs, which tree it prunes, where the reference workloads live, and whether the raw log is kept |

## Further reading

- [`tests/README.md`](https://github.com/ls1intum/phobos/blob/main/tests/README.md): every
  suite, one row each
- [How can you contribute](how-can-you-contribute.md): the lint gate beside these suites
