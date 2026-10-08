# The suites

Every suite here reports its own passed, failed and skipped counts and exits non-zero on a
failure. **A skipped check is not a passing one.** Where a suite can skip, the table says
what makes it skip and what turns that skip into a failure, because a skip reads as a pass
in a workflow summary.

Each shell suite is run by a step of its own in CI, so one run names every suite that broke
rather than only the first. The Python suites are the exception: pytest runs them together in
one step and reports each failure itself. A step of `test.yml` fails when a shell file under `tests/` is
named in no workflow, so a suite cannot sit in the tree and run nowhere. The exceptions are the helpers that
are not suites: `harness.sh`, the matrix `lib.sh` and `run-all.sh`, and `policy-redundancy-probe.sh`.

The unit suites live under `tests/unit/` in the same folder structure as `core/`, one folder
per core component they test, and the integration suites live under `tests/integration/`,
with the acceptance suites in `tests/integration/landlock-filesystem-and-networksystem-acceptance/`.
The shared harness and the diagnostics stay at the `tests/` root.

Every suite reports through `harness.sh`, which it sources and which owns `ok`, `bad`,
`skip`, `check`, the three counters and `finish`. A suite keeps everything else of its own:
its shell options, its fixtures and its cleanup trap. `harness.sh` sits at the `tests/` root,
so a suite reaches it relative to its own depth: `../harness.sh` from `tests/integration/`,
`../../harness.sh` from a unit folder or the acceptance folder. The acceptance CI step
therefore mounts `tests/` rather than
`tests/integration/landlock-filesystem-and-networksystem-acceptance/`.

## Host suites, run by the `Shell suites` job of `test.yml`

These need a shell, a compiler, a Python and Bubblewrap. No container, no kernel feature
and no elevated permission.

| Suite | What it proves | Skips when |
| --- | --- | --- |
| `cli_flags.sh` | the command line of `phobos.sh`: the layer switches, the refusal of an unknown option, where the command's own arguments begin, the exit statuses, and that every `PHB_` name a script reads is one something assigns | never |
| `startup_environment.sh` | every entry point, `phobos.sh` and each layer on its own, before it runs anything: a program planted under every name in the current directory, in a relative directory and in a `~` directory is never run through a `PATH` of `.:`, `:`, a trailing or doubled colon, `relative/dir:` or `~/bin:`, the command then sees only the absolute entries, a clean absolute `PATH` reaches the command unchanged, a `PATH` with no absolute entry is refused with `PHB-ERUNTIME`, `CDPATH` never redirects an entry point's own `cd`, a relative `TMPDIR`, `HOSTALIASES` or `TZDIR` and the relative entries of `GCONV_PATH`, `LOCPATH` and `NLSPATH` are dropped while absolute ones are kept, and with no `PATH` at all the command is given none and nothing is said. Started as a program under a `PATH` beginning with `.`, no entry point runs a planted `bash`, since each `#!` line names `/bin/bash`, a layer run on its own starts itself again through `/bin/bash`, never a `bash` first in an absolute `PATH` entry, and under a `PATH` without `dirname` every entry point still finds its own files | never |
| `scratch_location.sh` | every temporary file `phobos.sh`, the policy program, the network layer and the filesystem layer make lies in the run's own specification directory, recorded through a logging `mktemp`, and the run works with a `TMPDIR` that names no directory; a `PHOBOS_SCRATCH` left in the environment is never used; a helper called with no scratch directory refuses with `PHB-ERUNTIME` and makes nothing in `TMPDIR` | never |
| `signals.sh` | `run_forwarding_signals`, which every layer waits through: SIGTERM, SIGHUP, SIGINT and SIGQUIT sent to the layer reach its command, the status is the command's own (exit codes, a killed command, a command that handles the signal), standard input stays the command's, the layer's own traps are put back exactly (an ignored TERM, a trap whose text names another signal), and a job started before the command is never signalled | never |
| `timeout_units.sh` | the timeout contract: how a value is parsed, merged and canonicalised, and when a status counts as a timeout | never |
| `timeout_escalation.sh` | a command that ignores SIGTERM is still stopped, by the `--kill-after` escalation | GNU `timeout` or a C compiler is absent. A probe that does not compile is a failure, not a skip |
| `limit_merge.sh` | the timeout and the resource limits merge across configurations: zero disables and wins, otherwise the largest value | never |
| `resource_limits.sh` | the `[limits]` keys are parsed and applied as rlimits, and a malformed one is refused | never |
| `policy_program.sh` | `phobos-policysystem.sh` writes the specification, the model is additive, a run without a base policy is refused, and an unenforceable network rule is refused before anything is written; `[bind]` takes port 0 and nothing like `00` | never |
| `malformed_cfg.sh` | a configuration file that is wrong is refused with PHB-EPOLICY and a message that says what is wrong and in which file and line, with no bash error or raw byte in it: a file that is not readable, a byte order mark, a NUL byte, Windows line endings, a path that is not absolute, digits that are not ASCII, numbers too long for the arithmetic, and the same file-level refusals for an Ares 2 policy, invalid UTF-8 and a tab included | never |
| `network_policy.sh` | how a `[connect]` and a `[bind]` section become Landlock port rules, including the cases that are refused, and that the network layer refuses a `[connect]` name rule when the egress broker is off. Port 0 in `[bind]` becomes the ephemeral grant, a udp `[connect]` rule brings the udp grant, and the layer always hands its enforcer `--close-bind`, tells the guard what the policy grants and forwards the operator's minimum Landlock version | never |
| `filesystem_policy.sh` | how the filesystem sections become Landlock path rules: a nested entry narrower than its ancestor is refused as unenforceable, a redundant one and a merely different one are allowed, and the redundant one is what lets an exercise config name that path with fewer rights | never |
| `address_literals.sh` | the spellings of an address, a range and a port in a `[connect]` line: every well-formed IPv4 and IPv6 address, range and port is accepted, and every almost-right one (a short or long dotted quad, a decimal address, a leading zero, a zone, two `::`, a prefix of 0 or past the width, an empty port) is refused as a policy error | never |
| `yaml_subset.sh` | the strict YAML subset an Ares 2 policy may be written in: each accepted construct (block mappings, both sequence indentations, the empty flow collections, both quote styles, comments, a leading `---`, non-ASCII text in valid UTF-8) becomes the exact records, and each construct two YAML readers could read differently (anchors, aliases, tags, block scalars, flow items, a second document, a duplicate key, a tab, a carriage return, a byte order mark, a NUL, invalid UTF-8, a control or bidirectional character in a value, an ambiguous boolean or number, an escape other than `\\` and `\"`, a continuation line) is refused as a policy error naming its line | never |
| `language_configuration.sh` | how a programming language configuration is read: both kinds of `[base]` entry resolve to the base they name, and `environment` (with and without a fallback), `command-ancestor` (through a chain of symbolic links), `fixed` and `password-database home` (the home field of this uid's password database entry, not `HOME`) determine their values; an unknown section or primitive, a value that is not an absolute existing directory, a command not on the `PATH` (one in the current directory included), a variable that is only a shell variable, a `[base]` entry that is absolute, holds `..`, is missing or links out of its folder, a `[connect]` line that is malformed or is not a loopback rule without a port, a password database with no entry for the uid, a home field shorter than two characters (empty or `/`, for which a JVM from version 19 uses `HOME` instead), relative or missing, a control character in the entry or an entry of the wrong number of fields, a configuration with no file, CR, BOM and NUL are refused with file and line, and a `printenv` or `getent` that cannot be run ends the run with PHB-ERUNTIME; a placeholder is determined only when it is used: one whose source cannot be determined does not refuse a run that never uses it and is refused, with the configuration's file and line, once used, one used twice asks its source once, and one the configuration does not name is refused where it was used; every shipped configuration loads | never |
| `no_language_in_code.sh` | no script, helper or C source under `core/` outside `core/config/` names an Ares 2 configuration (`JAVA_USING`) or a Java placeholder (`java.home`, `user.home`, `java.io.tmpdir`), and the same search does find them in the programming language configurations, so it is not vacuous | never |
| `ares_policy.sh` | how an Ares 2 policy becomes the parsed state a `.cfg` gives: every file system flag maps to its sections (`[create-symlink]` with create, `[restructure]` with create and delete), a granted network entry becomes a TCP and a UDP rule for each host shape, milliseconds become seconds exactly and the tightest timeout wins; the refusals are refused with file and line (schema, types, version, placeholders, `*`, `..`, a missing path under each right, all six partial network flag combinations, port 0 beyond loopback, a trailing dot); the shapes of the Ares 2 repository's two example policies are read, the Maven one refused for want of its configuration; a path that reaches the project root through a symbolic link or a name for the root that leads elsewhere is refused, while links that lead away from the root and a root-less run are untouched, and a project root that is `/` or reaches its directory through a link is refused; the covered-entry skip leaves out only a row the base covers through a resolved ancestor; two policies naming different configurations are refused | never |
| `ares_policy_program.sh` | `phobos-policysystem.sh` given an Ares 2 policy: the configuration folds only its own bases and its `[connect]` rows while a `.cfg`-only run still folds every `Base*.cfg` and gets no UDP row, the import merges with a `.cfg` the same in either order, a base row is never removed and a strict-subset `.cfg` row is still refused, the specification of an Ares policy equals that of the hand-written `.cfg` of the same meaning, a non-loopback host with port 0 is refused at its line, the project root comes from `--project-root`, else the tail's last `--chdir`, else nothing, and an empty, relative, missing, `/`, linked or `..` `--project-root` is refused, also through `phobos.sh`, a policy path through a link inside the project root is refused with its file and line while the same through a link outside it is imported, and a misnamed file is refused by both readers | never |
| `seccomp_networksystem.sh` | the connect guard enforces the allow-list by host, port and transport, and refuses what it cannot carry. The transport half is pinned in both directions: a `tcp` rule admits no datagram to the same host and port, and a `udp` rule admits no stream connect to it. A `listen()` is run by the guard on a socket it created: a bound socket listens and its port is free again once closed, an unbound socket is refused, an inherited one is refused, and a thread swapping an unbound socket under the descriptor never creates a listener, with a control without the guard that does. Every datagram connect and send is made by the guard from copies: `sendto`, `sendmsg` and `sendmmsg` arrive intact and `sendmmsg` reports each length, a socket never bound, an inherited one, ancillary data and an oversize datagram are refused, and a thread rewriting the destination while each of the four calls runs never reaches the forbidden receiver, with a control without the guard that does (skipped on a machine where that control never leaks). The guard's resolve mode is run against a stub name server: addresses of both families, an alias, a changed case, a first query that is not answered, the sixteen-address limit, and every refusal (no address, an error, a truncated, malformed, mistaken or missing answer). Through the network layer, a name in a udp rule leads to its own address and a datagram there arrives, another address on the same port is refused, `/etc/hosts` and the specification directory are as they were afterwards, and a resolver that does not answer refuses the run before the command starts | the kernel has no seccomp user-notification, or no C compiler is installed at all; `gcc-14` is preferred and plain `gcc` is used when it is absent |
| `haproxy_conf.sh` | how a `[connect]` section becomes the egress broker's config: a host name becomes a TLS-name allow, an address becomes a destination allow, and everything else is refused; where `haproxy` is installed it also checks a generated config parses | never |
| `haproxy_broker.sh` | the egress broker enforces the allow-list by the TLS host name: a connection whose ClientHello names an allowed host reaches the destination, a forbidden one does not; end to end, the network layer's name mapping and broker are gone once the run has ended | a C compiler, `haproxy`, `openssl` or a kernel with seccomp user-notification is absent |
| `haproxy_inbound.sh` | the inbound filter in front of a listener admits only the source addresses an `[accept]` rule names, rejects every other, admits no one for a service with no source, and frees its public port when it stops | a C compiler or `haproxy` is absent |
| `hosts_entries.sh` | the lines a run adds to a hosts file carry its tag and are removed with its specification directory, in place and under a lock, leaving other runs' and the image's lines byte for byte; a failed removal keeps the directory for an outer layer | never |
| `denial_report.sh` | the denial report, both directions, and that neither it nor its helpers cost the command its output or its exit status | never |
| `prune_producer.sh` | what the prune phase produces: a run that finishes with artefacts missing, and one that leaves an earlier run's artefacts in place, both stop the merge | never |
| `layer_prune_observer.sh` | run in the prune image: its base grants nothing and is accepted, strace sees a Landlock refusal inside the shipped chain while a granted read works, the parser and attribution turn the record into exactly that denial, and every policy the renderer writes is accepted by the parser while the strict subset it refuses is refused by `phobos.sh` too | never |
| `layer_prune.sh` | run in the prune image: the layer pruner prunes the fixture under `layer-prune-fixture/` end to end; the derived policy passes the fixture's build with every layer on, grants its `/proc/self/status` read as a per-run name, refuses what the build did not need (an unneeded file, an optional one, a prefix sibling, a write into what was read, `10.0.0.1:80`, port 8080), bounds each limit below its default with every containment check refused; the orchestrator merges the result, the fixture passes under the merged base and its own file, and a `.cfg` its record does not vouch for stops the merge; a flaky reference, NO-SOURCE, a needed `setsid`, a needed external host and a failure no refusal explains each abort without a policy | never; the nproc containment check is recorded unchecked as root, which the kernel exempts |
| `layer_prune_egress.sh` | run in the prune image, `--network none`: of two hosts the fixture declares, the one it needs keeps its rule and the other is dropped, with a stand-in resolver and TLS server on loopback; under the derived policy the egress broker closes a connect to the dropped host on the kept rule's port, the guard refuses it on any other port with `EACCES`, naming it in the ClientHello towards the kept host's address gets no answer, and a build that also needs an undeclared host aborts without a policy | never |
| `layer_prune_maven.sh` | run in the prune image of the JDK 25 run-phase image by the manual `prune-maven.yml`, not by `build.yml`: the image holds the manifest's bytes, the Maven reference exercise is pruned, merged and verified, its record shows both tests passed in every baseline run, every containment check refused, every grant under `/root` a single file and no write-class right there, and a copy without tests or with an absent version aborts and writes no policy | the image has no `/root/.m2/repository`, which is a failure, not a skip |
| `prune_sandbox.sh` | the real pruner against a fixture tree: how it reads a build's outcome, and that its sandbox hides what it says it hides | Bubblewrap cannot create a user namespace. `PHOBOS_REQUIRE_BWRAP=1`, which CI sets, turns that skip into a failure |
| `harness_self_test.sh` | the reporting every other suite depends on: a failure is recorded and the suite carries on, `bad` does not end a suite running under `set -e`, the exit status and the printed summary agree, and a skip is counted apart from a pass | never |
| `runner-capability-probe.sh` | not a suite: it answers what a machine can do, and is run by `runner-capabilities.yml` on request, on each hosted runner image for the KVM question. It reports for itself rather than through the harness, because its statuses are its own | it is a diagnostic; the assert modes answer 0, 1 or 3. `--assert-kvm` needs QEMU and a readable kernel image, and `--assert-ptrace` needs gcc with a static libc and docker; each says indeterminate without them |
| `policy-redundancy-probe.sh` | not a suite and not in CI: it names the entries of a policy that grant Landlock nothing an ancestor already grants, for reading a freshly pruned policy. Those entries are not dead, so it reports and never fails; `AGENTS.md` says what they do. Run it where the policy is applied, since it resolves symbolic links | it is a diagnostic; it answers 0 unless it was called wrongly |

## Python suites, run by the `Python helpers` job of `test.yml`

The second job of the same workflow installs pytest and runs `python -m pytest tests/python`.
It needs no container, no Bubblewrap and no compiler: the pruning entry point is replaced by a
shell stub, so these drive the helpers alone.

| Suite | What it proves | Skips when |
| --- | --- | --- |
| `python/test_orchestrate.py` | every way a language can drop out of a prune stops the merge rather than shrinking it: a language that fails, one that produces nothing, one whose artefacts disagree with the record written beside them, an aborted exercise, artefacts of both producers, and an `[execute]` that would join a write; what the merge writes (union, limits, exercise files). It drives the orchestrator as a subprocess, which is what keeps the entry point honest | never |
| `python/test_orchestrate_helpers.py` | the orchestrator's parts, which a subprocess test cannot reach on their own: that importing it does no work, how it reads a path set and judges a pair of artefacts, that every language really is pruned at the same time, and that the layout and the arguments reach each worker unchanged | never |
| `python/test_make_lang_sets.py` | the union never drops a path a run asked for, the intersection never keeps one a run did not, an earlier run's own output is never folded back in as a fresh result, and no input at all stops rather than writing an empty policy | never |

## Unit suites, run by `build.yml`

C, compiled with `gcc-14` and run without a kernel feature: every syscall the code under
test makes is interposed.

| Suite | What it covers | Coverage gate |
| --- | --- | --- |
| `unit/phobos-landlock-filesystem-and-networksystem/run.sh` | `phobos-landlock-filesystem-and-networksystem`: the options, the path rules, the ruleset | none; `mutation.sh` in the same folder measures this suite instead, because the coverage runtime disturbs the calls it interposes |
| `unit/phobos-seccomp-networksystem/seccomp_networksystem_run.sh` | the connect guard: the filter, the supervisor, the socket types, the held sockets and the listen decision, the rules | every line, with `--coverage` |
| `unit/phobos-landlock-filesystem-and-networksystem/mutation.sh` | mutation testing of the Landlock suite, the `mutation` job of `build.yml`, on every change and weekly. It needs clang 20 and mull 0.34.1 in an Ubuntu 26.04 container. A processor-time limit ends a mutant whose loop never ends, whose forked child would otherwise hold the run | reports a score, and fails where no score is reached; it is not a gate on the score |

## Acceptance suites, run by `build.yml` inside the run-phase image

Each runs in an **ordinary** container: no `--privileged`, no `--cap-add`, no
`--security-opt`, and `--network none`. `tests/integration/landlock-filesystem-and-networksystem-acceptance/README.md` says how to
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

## The protection matrix, run by `build.yml` inside the run-phase image

Eleven suites in `tests/integration/protection-matrix/` hold the whole of `phobos.sh` to what it
promises, each in a step of its own. They run in an ordinary container with `--network none`, plus
`--memory` and `--pids-limit`, which are cgroup caps and not privileges. Every denial has an
unprotected control and a run with only its layer switched off, a check whose control fails is
skipped rather than passed, and a limit the documentation admits is asserted as it is. A skip there
is an open defect, named in the suite's own README, which turns red the moment it is fixed, or a check
that cannot run here and says why: a control the container's seccomp profile blocks, a Landlock version
the kernel lacks, a missing tool or too few processor cores.
`tests/integration/protection-matrix/README.md` says how they are built and what they do not cover.

| Suite | What it proves |
| --- | --- |
| `filesystem.sh` | each filesystem right on its own, what it does not grant, inheritance by children, escape attempts, and the documented gaps; a tree granted by an imported Ares 2 policy, and what the import does not grant |
| `network.sh` | TCP and UDP connect, the destination race, bind and listen closed, `[accept]` filtering, and host names through the egress broker; an imported Ares 2 network entry as TCP and UDP under a programming language configuration, on every kernel |
| `timeout.sh` | a run and everything it started ends at the limit, and no process escapes the group; an imported Ares 2 timeout in milliseconds, not rounded |
| `resources.sh` | every limit is set, read back, enforced, inherited, merged and validated |
| `combinations.sh` | all sixteen subsets of switched-off layers, with one witness per layer in each |
| `cli.sh` | the command line, streams, the environment, overrides, tail flags and odd policy files |
| `lifecycle.sh` | nothing is left behind after any ending of a run, a concurrent command sees none of a run's temporary files in `/tmp`, a signal sent to `phobos.sh` is pinned as it is (it never reaches the command, a known defect) |
| `policy-syntax.sh` | every shape of a policy line, accepted or refused with its status, and every limit read back from the kernel; Ares 2 policies accepted and refused |
| `network-edge.sh` | range ends, port boundaries, special addresses, IPv6 spellings, socket kinds, a TCP destination rewritten during connect |
| `filesystem-edge.sh` | links, dot-dot, magic links, rights on files and the root, odd names, a link swapped while it is opened |
| `resources-edge.sh` | each limit met through the call that meets it, and the limits Phobos does not set |

## The environment variables the suites read

| Variable | Read by | Meaning |
| --- | --- | --- |
| `PHOBOS_REQUIRE_BWRAP` | `prune_sandbox.sh` | any non-empty value turns a Bubblewrap skip into a failure |
| `COMPILER` | the unit runners | the compiler to build the C under test with; `gcc-14` by default |
| `COVERAGE_TOOL` | the unit runners | the gcov that matches that compiler; `gcov-14` by default |
| `PHOBOS_HOME` | the acceptance suites | where Phobos is installed in the image; `/var/tmp/opt/core` by default |
| `PROBE_CONTAINER_IMAGE` | `runner-capability-probe.sh` | the image the container half of the probe runs in |
| `PRUNE_LOG_DIR`, `PRUNE_TARGET`, `TESTING_DIR`, `PHOBOS_KEEP_LOG` | the prune suites and the pruner itself | where a prune writes its logs, which tree it prunes, where the exercises live, and whether the raw log is kept |
