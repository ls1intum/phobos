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

## One harness, four families

Every suite sources `tests/harness.sh`, which owns `ok`, `bad`, `skip`, `check`, the three
counters and `finish`. A suite keeps everything else of its own: its shell options, its
fixtures and its cleanup trap. Each reports its own passed, failed and skipped counts and exits
non-zero on a failure.

| Family | Where | What it needs | Run by |
| --- | --- | --- | --- |
| Host suites | `tests/*.sh` | a shell, a compiler, a Python and Bubblewrap | the `Shell suites` job of `test.yml`, in continuous integration (CI) |
| Python suites | `tests/python/` | pytest | the `Python helpers` job of `test.yml` |
| Unit suites | `tests/unit/` | `gcc-14`, no kernel feature | `build.yml` |
| Acceptance suites | `tests/landlock-acceptance/` | the run-phase image, an ordinary container | `build.yml` |

Each shell suite is a CI step of its own, so one run names every suite that broke rather than
the first alone. `tests/README.md` is the table of every suite, what it proves and what makes it
skip.

## A skipped check is not a passing one

Where a suite can skip, its row in `tests/README.md` says what makes it skip and what turns
that skip into a failure. Two examples carry the principle:

- `prune_sandbox.sh` skips where Bubblewrap cannot create a user namespace.
  `PHOBOS_REQUIRE_BWRAP=1`, which CI sets, turns that skip into a failure.
- `timeout_escalation.sh` skips where GNU `timeout` or a compiler is absent. A probe that does
  not compile is a failure rather than a skip, because a probe that fails to build proves
  nothing about the escalation it was meant to measure.

## The unit suites interpose rather than run

The C unit suites compile the code under test and interpose every system call it makes, so
they need no kernel feature and no privilege. That is what lets them exercise a Landlock
version the runner does not have, and a failure path the kernel would never produce to order.

Only one of them carries a coverage gate:

| Suite | Gate |
| --- | --- |
| `unit/connect_guard_run.sh` | every line, with `--coverage` |
| `unit/run.sh` | none. `unit/mutation.sh` reports a mutation score for it weekly instead, because the coverage runtime disturbs the calls the suite interposes |

## The acceptance suites measure the real sandbox

They run inside the run-phase image, in an **ordinary** container: no `--privileged`, no
`--cap-add`, no `--security-opt`, and `--network none`. A suite that needed any of those would
be measuring a different sandbox from the one a command gets, which is why that constraint is
part of the convention rather than part of the setup.

Seven suites cover, in order: the five guarantees of the shipped policy, inheritance by a
second process and a non-root run, rights tightened and widened across four phases, the policy
the image ships running a real build, a raw `connect()` refused by a Landlock port
rule, Landlock scoping against signals and abstract sockets, and the connect guard inside the
image.

## Both directions, always

A change to the sandbox needs two tests, not one:

- the permitted case still works, which says the sandbox is usable;
- the nearest forbidden neighbour is still denied, which says the boundary held.

Either alone passes for the wrong reason. `tests/filesystem_policy.sh` is the worked example:
it pins that a nested entry narrower than its ancestor is refused **and** that a merely
different one is allowed, because a change that tightened the first would silently break the
second.

## The probes are not suites

Two scripts under `tests/` report for themselves and never fail a run:

- `runner-capability-probe.sh` answers what a machine can do, and is run by
  `runner-capabilities.yml` on request.
- `policy-redundancy-probe.sh` names the entries of a policy that grant Landlock nothing an
  ancestor already grants. Those entries are not dead code, so it reports rather than failing.
  Run it where the policy is applied, since it resolves symbolic links.

## The environment variables the suites read

| Variable | Read by | Meaning |
| --- | --- | --- |
| `PHOBOS_REQUIRE_BWRAP` | `prune_sandbox.sh` | any non-empty value turns a Bubblewrap skip into a failure |
| `COMPILER` | the unit runners | the compiler to build the C under test with, `gcc-14` by default |
| `COVERAGE_TOOL` | the unit runners | the gcov matching that compiler, `gcov-14` by default |
| `PHOBOS_HOME` | the acceptance suites | where Phobos is installed in the image, `/var/tmp/opt/core` by default |
| `PROBE_CONTAINER_IMAGE` | `runner-capability-probe.sh` | the image the container half of the probe runs in |
| `PRUNE_LOG_DIR`, `PRUNE_TARGET`, `TESTING_DIR`, `PHOBOS_KEEP_LOG` | the prune suites and the pruner | where a prune writes its logs, which tree it prunes, where the reference workloads live, and whether the raw log is kept |

## Further reading

- [`tests/README.md`](https://github.com/ls1intum/phobos/blob/main/tests/README.md) — every
  suite, one row each
- [How can you contribute](how-can-you-contribute.md) — the lint gate beside these suites
