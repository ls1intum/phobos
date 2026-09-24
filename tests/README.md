# The suites

Every suite here reports its own passed, failed and skipped counts and exits non-zero on a
failure. **A skipped check is not a passing one.** Where a suite can skip, the table says
what makes it skip and what turns that skip into a failure, because a skip reads as a pass
in a workflow summary.

Each shell suite is run by a step of its own in CI, so one run names every suite that broke
rather than only the first. The Python suites are the exception: pytest runs them together in
one step and reports each failure itself.

Every suite reports through `harness.sh`, which it sources and which owns `ok`, `bad`,
`skip`, `check`, the three counters and `finish`. A suite keeps everything else of its own:
its shell options, its fixtures and its cleanup trap. The acceptance suites reach it as
`../harness.sh`, which is why their CI step mounts `tests/` rather than
`tests/landlock-filesystem-and-networksystem-acceptance/`.

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
| `policy_program.sh` | `phobos-policysystem.sh` writes the specification, the model is additive, a run without a base policy is refused, and an unenforceable network rule is refused before anything is written | never |
| `network_policy.sh` | how a `[connect]` and a `[bind]` section become Landlock port rules, including the cases that are refused, and that the network layer refuses a `[connect]` name rule when the egress broker is off | never |
| `filesystem_policy.sh` | how the filesystem sections become Landlock path rules: a nested entry narrower than its ancestor is refused as unenforceable, a redundant one and a merely different one are allowed, and the redundant one is what lets an exercise config name that path with fewer rights | never |
| `seccomp_networksystem.sh` | the connect guard enforces the allow-list by host, port and transport, and refuses what it cannot carry. The transport half is pinned in both directions: a `tcp` rule admits no datagram to the same host and port, and a `udp` rule admits no stream connect to it | the kernel has no seccomp user-notification, or no C compiler is installed at all; `gcc-14` is preferred and plain `gcc` is used when it is absent |
| `haproxy_conf.sh` | how a `[connect]` section becomes the egress broker's config: a host name becomes a TLS-name allow, an address becomes a destination allow, and everything else is refused; where `haproxy` is installed it also checks a generated config parses | never |
| `haproxy_broker.sh` | the egress broker enforces the allow-list by the TLS host name: a connection whose ClientHello names an allowed host reaches the destination, a forbidden one does not | a C compiler, `haproxy`, `openssl` or a kernel with seccomp user-notification is absent |
| `denial_report.sh` | the denial report, both directions, and that neither it nor its helpers cost the command its output or its exit status | never |
| `prune_producer.sh` | what the prune phase produces: a run that finishes with artefacts missing, and one that leaves an earlier run's artefacts in place, both stop the merge | never |
| `prune_sandbox.sh` | the real pruner against a fixture tree: how it reads a build's outcome, and that its sandbox hides what it says it hides | Bubblewrap cannot create a user namespace. `PHOBOS_REQUIRE_BWRAP=1`, which CI sets, turns that skip into a failure |
| `harness_self_test.sh` | the reporting every other suite depends on: a failure is recorded and the suite carries on, `bad` does not end a suite running under `set -e`, the exit status and the printed summary agree, and a skip is counted apart from a pass | never |
| `runner-capability-probe.sh` | not a suite: it answers what a machine can do, and is run by `runner-capabilities.yml` on request. It reports for itself rather than through the harness, because its statuses are its own | it is a diagnostic; the assert modes answer 0, 1 or 3 |
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
| `unit/run.sh` | `phobos-landlock-filesystem-and-networksystem`: the options, the path rules, the ruleset | none; `unit/mutation.sh` measures this suite weekly instead, because the coverage runtime disturbs the calls it interposes |
| `unit/seccomp_networksystem_run.sh` | the connect guard: the filter, the supervisor, the socket types, the rules | every line, with `--coverage` |
| `unit/mutation.sh` | mutation testing of the Landlock suite, weekly | reports a score; it is not a gate |

## Acceptance suites, run by `build.yml` inside the run-phase image

Each runs in an **ordinary** container: no `--privileged`, no `--cap-add`, no
`--security-opt`, and `--network none`. `tests/landlock-filesystem-and-networksystem-acceptance/README.md` says how to
run them by hand.

| Suite | What it proves |
| --- | --- |
| `run-tests.sh` | the five guarantees: the permitted paths work, the forbidden ones are denied, and the boundary holds for a network endpoint too |
| `extra-tests.sh` | inheritance by a second process, a non-root run, the control probe, and the options no policy file reaches |
| `phase-test.sh` | rights tightened and widened across four phases, and the trap of an unrestricted final phase |
| `shipped-policy-test.sh` | the policy the image actually ships runs a real build |
| `network-port-test.sh` | a raw `connect()` syscall is still refused by Landlock's port rule |
| `scoping-test.sh` | Landlock scoping: a sandboxed process can neither signal a process outside its domain nor reach an abstract UNIX socket there |
| `seccomp-networksystem-test.sh` | the connect guard inside the image: an allowed destination connects, a forbidden one is refused, neither can be redirected, and a rule for one transport admits nothing on the other |

## The environment variables the suites read

| Variable | Read by | Meaning |
| --- | --- | --- |
| `PHOBOS_REQUIRE_BWRAP` | `prune_sandbox.sh` | any non-empty value turns a Bubblewrap skip into a failure |
| `COMPILER` | the unit runners | the compiler to build the C under test with; `gcc-14` by default |
| `COVERAGE_TOOL` | the unit runners | the gcov that matches that compiler; `gcov-14` by default |
| `PHOBOS_HOME` | the acceptance suites | where Phobos is installed in the image; `/var/tmp/opt/core` by default |
| `PROBE_CONTAINER_IMAGE` | `runner-capability-probe.sh` | the image the container half of the probe runs in |
| `PRUNE_LOG_DIR`, `PRUNE_TARGET`, `TESTING_DIR`, `PHOBOS_KEEP_LOG` | the prune suites and the pruner itself | where a prune writes its logs, which tree it prunes, where the exercises live, and whether the raw log is kept |
