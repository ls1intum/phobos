# The suites

Every suite here reports its own passed, failed and skipped counts and exits non-zero on a
failure. **A skipped check is not a passing one.** Where a suite can skip, the table says
what makes it skip and what turns that skip into a failure, because a skip reads as a pass
in a workflow summary.

Each shell suite is run by a step of its own in CI, so one run names every suite that broke
rather than only the first. The Python suites are the exception: pytest runs them together in
one step and reports each failure itself.

## Host suites, run by the `Shell suites` job of `test.yml`

These need a shell, a compiler, a Python and Bubblewrap. No container, no kernel feature
and no elevated permission.

| Suite | What it proves | Skips when |
| --- | --- | --- |
| `cli_flags.sh` | the command line of `phobos.sh`: the layer switches, the refusal of an unknown option, where the command's own arguments begin, the exit statuses, and that every `PHB_` name a script reads is one something assigns | never |
| `timeout_units.sh` | the timeout contract: how a value is parsed, merged and canonicalised, and when a status counts as a timeout | never |
| `timeout_escalation.sh` | a command that ignores SIGTERM is still stopped, by the `--kill-after` escalation | GNU `timeout` or a C compiler is absent. A probe that does not compile is a failure, not a skip |
| `limit_merge.sh` | the timeout and the resource limits merge across configurations: zero disables and wins, otherwise the largest value | never |
| `resource_limits.sh` | the `[limits]` keys are parsed and applied as rlimits, and a malformed one is refused | never |
| `policy_program.sh` | `phobos-policy.sh` writes the specification, the model is additive, a run without a base policy is refused, and an unenforceable network rule is refused before anything is written | never |
| `network_policy.sh` | how a `[connect]` and a `[bind]` section become Landlock port rules, including the cases that are refused | never |
| `filesystem_policy.sh` | how the filesystem sections become Landlock path rules: a nested entry narrower than its ancestor is refused as unenforceable, a redundant one and a merely different one are allowed, and the redundant one is what lets an exercise config name that path with fewer rights | never |
| `network_cache_ports.sh` | the address cache of `libnetblocker` and its port restrictions, against the real library | the compiler named by `COMPILER`, `gcc-14` by default, is absent. There is no fallback: the library has to be built the way the image builds it. Three checks skip on their own where the host has no IPv6 loopback |
| `connect_guard.sh` | the connect guard enforces the allow-list by host and port, and refuses what it cannot carry | the kernel has no seccomp user-notification, or no C compiler is installed at all; `gcc-14` is preferred and plain `gcc` is used when it is absent |
| `denial_report.sh` | the denial report, both directions, and that neither it nor its helpers cost the command its output or its exit status | never |
| `prune_producer.sh` | what the prune phase produces: a run that finishes with artefacts missing, and one that leaves an earlier run's artefacts in place, both stop the merge | never |
| `prune_sandbox.sh` | the real pruner against a fixture tree: how it reads a build's outcome, and that its sandbox hides what it says it hides | Bubblewrap cannot create a user namespace. `PHOBOS_REQUIRE_BWRAP=1`, which CI sets, turns that skip into a failure |
| `runner-capability-probe.sh` | not a suite: it answers what a machine can do, and is run by `runner-capabilities.yml` on request | it is a diagnostic; the assert modes answer 0, 1 or 3 |
| `policy-redundancy-probe.sh` | not a suite and not in CI: it names the entries of a policy that grant Landlock nothing an ancestor already grants, for reading a freshly pruned policy. Those entries are not dead, so it reports and never fails; `AGENTS.md` says what they do. Run it where the policy is applied, since it resolves symbolic links | it is a diagnostic; it answers 0 unless it was called wrongly |

## Python suites, run by the `Python helpers` job of `test.yml`

The second job of the same workflow installs pytest and runs `python -m pytest tests/python`.
It needs no container, no Bubblewrap and no compiler: the pruning entry point is replaced by a
shell stub, so these drive the helpers alone.

| Suite | What it proves | Skips when |
| --- | --- | --- |
| `python/test_orchestrate.py` | every way a language can drop out of a prune stops the merge rather than shrinking it: a language that fails, one that produces nothing, one whose artefacts disagree with the record written beside them. It drives the orchestrator as a subprocess, which is what keeps the entry point honest | never |
| `python/test_orchestrate_helpers.py` | the orchestrator's parts, which a subprocess test cannot reach on their own: that importing it does no work, how it reads a path set and judges a pair of artefacts, that every language really is pruned at the same time, and that the layout and the arguments reach each worker unchanged | never |
| `python/test_make_lang_sets.py` | the union never drops a path a run asked for, the intersection never keeps one a run did not, an earlier run's own output is never folded back in as a fresh result, and no input at all stops rather than writing an empty policy | never |

## Unit suites, run by `build.yml`

C, compiled with `gcc-14` and run without a kernel feature: every syscall the code under
test makes is interposed.

| Suite | What it covers | Coverage gate |
| --- | --- | --- |
| `unit/run.sh` | `phobos-landlock`: the options, the path rules, the ruleset | none; `unit/mutation.sh` measures this suite weekly instead, because the coverage runtime disturbs the calls it interposes |
| `unit/netblocker_run.sh` | `libnetblocker`: the rules, the address cache, every hook | every line and every branch, with `--coverage` |
| `unit/connect_guard_run.sh` | the connect guard: the filter, the supervisor, the socket types, the rules | every line, with `--coverage` |
| `unit/mutation.sh` | mutation testing of the Landlock suite, weekly | reports a score; it is not a gate |

## Acceptance suites, run by `build.yml` inside the run-phase image

Each runs in an **ordinary** container: no `--privileged`, no `--cap-add`, no
`--security-opt`, and `--network none`. `tests/landlock-acceptance/README.md` says how to
run them by hand.

| Suite | What it proves |
| --- | --- |
| `run-tests.sh` | the five guarantees: the permitted paths work, the forbidden ones are denied, and the boundary holds for a network endpoint too |
| `extra-tests.sh` | inheritance by a second process, a non-root run, the control probe, and the options no policy file reaches |
| `phase-test.sh` | rights tightened and widened across four phases, and the trap of an unrestricted final phase |
| `shipped-policy-test.sh` | the policy the image actually ships runs a real build |
| `network-port-test.sh` | a raw `connect()` syscall, which steps around the preload library, is still refused by Landlock's port rule |
| `bind-address-test.sh` | a `[bind]` rule is enforced by port, and the local address by the preload library |
| `scoping-test.sh` | Landlock scoping: a sandboxed process can neither signal a process outside its domain nor reach an abstract UNIX socket there |
| `connect-guard-test.sh` | the connect guard inside the image: an allowed destination connects, a forbidden one is refused, and neither can be redirected |

## The environment variables the suites read

| Variable | Read by | Meaning |
| --- | --- | --- |
| `PHOBOS_REQUIRE_BWRAP` | `prune_sandbox.sh` | any non-empty value turns a Bubblewrap skip into a failure |
| `COMPILER` | the unit runners, `network_cache_ports.sh` | the compiler to build the C under test with; `gcc-14` by default |
| `COVERAGE_TOOL` | the unit runners | the gcov that matches that compiler; `gcov-14` by default |
| `PHOBOS_HOME` | the acceptance suites | where Phobos is installed in the image; `/var/tmp/opt/core` by default |
| `NETBLOCKER_SO_FOR_RUN` | `network_cache_ports.sh` | a prebuilt library to test against instead of building one |
| `PROBE_CONTAINER_IMAGE` | `runner-capability-probe.sh` | the image the container half of the probe runs in |
| `PRUNE_LOG_DIR`, `PRUNE_TARGET`, `TESTING_DIR`, `PHOBOS_KEEP_LOG` | the prune suites and the pruner itself | where a prune writes its logs, which tree it prunes, where the exercises live, and whether the raw log is kept |
