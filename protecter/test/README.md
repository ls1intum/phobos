# The protecter suites

Every suite here reports its own passed, failed and skipped counts and exits non-zero on a
failure. **A skipped check is not a passing one.** Where a suite can skip, the table says
what makes it skip and what turns that skip into a failure, because a skip reads as a pass
in a workflow summary.

Each shell suite is run by a step of its own in CI, so one run names every suite that broke
rather than only the first. A step of `test.yml` fails when a shell file under `protecter/test/` or
`pruner/` is named in no workflow, so a suite cannot sit in the tree and run nowhere. The
exceptions are the helpers that are not suites: `harness.sh`, the matrix `lib.sh` and `run-all.sh`,
and `policy-redundancy-probe.sh`.

The unit suites live under `protecter/test/unit/` in the same folder structure as `protecter/src/`, one folder
per component they test, and the integration suites live under `protecter/test/integration/`,
with the acceptance suites in `protecter/test/integration/landlock-filesystem-and-networksystem-acceptance/`.
The shared harness and the diagnostics stay at the `protecter/test/` root. The pruner's suites are in
[`pruner/README.md`](../../pruner/README.md) and source the same harness.

Every suite reports through `harness.sh`, which it sources and which owns `ok`, `bad`,
`skip`, `check`, the three counters and `finish`. A suite keeps everything else of its own:
its shell options, its fixtures and its cleanup trap. `harness.sh` sits at the `protecter/test/` root,
so a suite reaches it relative to its own depth: `../harness.sh` from `protecter/test/integration/`,
`../../harness.sh` from a unit folder or the acceptance folder. The acceptance CI step
therefore mounts `protecter/test/` at `/tests` rather than
`protecter/test/integration/landlock-filesystem-and-networksystem-acceptance/`.

## Host suites, run by the `Shell suites` job of `test.yml`

These need a shell, a compiler and a Python. No container, no kernel feature and no elevated
permission.

| Suite | What it proves | Skips when |
| --- | --- | --- |
| `cli_flags.sh` | the command line of `phobos.sh`: the layer switches, the refusal of an unknown option, where the command's own arguments begin, the exit statuses, and that every `PHB_` name a script reads is one something assigns | never |
| `phobos_cli.sh` | `phobos-cli.sh` without Docker: the options it accepts and the ones it refuses in both places (every layer switch, every enforcer override, any option not listed, a leaked `BASH_ENV` or `LD_*`), the `docker run` it builds for `run` with its network, memory and process limits and without any privilege, capability, device, host namespace or Docker socket, the configurations copied and mounted read-only, the project root kept inside the exercise, the dispatch table of `prune`, `record` and `build` (Compose anchored to the checkout against a decoy compose file and `.env`, a rebuild before every job, the image chosen by the key or the language), `prune all` stopping at the first of its seven jobs that fails and never ending with 0 when interrupted, and the image form against a stand-in installation | the stand-in installation or helpers cannot be made because the directory exists (a run inside an image), or no bash older than 4.4 is beside a newer one |
| `startup_environment.sh` | every entry point, `phobos.sh` and each layer on its own, before it runs anything: a program planted under every name in the current directory, in a relative directory and in a `~` directory is never run through a `PATH` of `.:`, `:`, a trailing or doubled colon, `relative/dir:` or `~/bin:`, the command then sees only the absolute entries, a clean absolute `PATH` reaches the command unchanged, a `PATH` with no absolute entry is refused with `PHB-ERUNTIME`, `CDPATH` never redirects an entry point's own `cd`, a relative `TMPDIR`, `HOSTALIASES` or `TZDIR` and the relative entries of `GCONV_PATH`, `LOCPATH` and `NLSPATH` are dropped while absolute ones are kept, and with no `PATH` at all the command is given none and nothing is said. Started as a program under a `PATH` beginning with `.`, no entry point runs a planted `bash`, since each `#!` line names `/bin/bash`, a layer run on its own starts itself again through `/bin/bash`, never a `bash` first in an absolute `PATH` entry, and under a `PATH` without `dirname` every entry point still finds its own files | never |
| `scratch_location.sh` | every temporary file `phobos.sh`, the policy program, the network layer and the filesystem layer make lies in the run's own specification directory, recorded through a logging `mktemp`, and the run works with a `TMPDIR` that names no directory; a `PHOBOS_SCRATCH` left in the environment is never used; a helper called with no scratch directory refuses with `PHB-ERUNTIME` and makes nothing in `TMPDIR` | never |
| `signals.sh` | `run_forwarding_signals`, which every layer waits through: SIGTERM, SIGHUP, SIGINT and SIGQUIT sent to the layer reach its command, the status is the command's own (exit codes, a killed command, a command that handles the signal), standard input stays the command's, the layer's own traps are put back exactly (an ignored TERM, a trap whose text names another signal), and a job started before the command is never signalled | never |
| `timeout_units.sh` | the timeout contract: how a value is parsed, merged and canonicalised, and when a status counts as a timeout | never |
| `timeout_escalation.sh` | a command that ignores SIGTERM is still stopped, by the `--kill-after` escalation, and a timed-out run, and only that, prints the blocked-action line for the time limit | GNU `timeout` or a C compiler is absent. A probe that does not compile is a failure, not a skip |
| `limit_merge.sh` | the timeout and the resource limits merge across configurations: zero disables and wins, otherwise the largest value | never |
| `resource_limits.sh` | the `[limits]` keys are parsed and applied as rlimits, a malformed one is refused, and a command that exhausts its CPU time or file size limit gets the matching blocked-action line, which a command that merely exits with the CPU limit's status without having used the CPU time does not (a file size limit exits 153, which a shell cannot tell from the signal) | never |
| `policy_program.sh` | `phobos-policysystem.sh` writes the specification, the model is additive, a run without a base policy is refused, and an unenforceable network rule is refused before anything is written; `[bind]` takes port 0 and nothing like `00` | never |
| `malformed_cfg.sh` | a configuration file that is wrong is refused with PHB-EPOLICY and a message that says what is wrong and in which file and line, with no bash error or raw byte in it: a file that is not readable, a byte order mark, a NUL byte, Windows line endings, a path that is not absolute, digits that are not ASCII, numbers too long for the arithmetic, and the same file-level refusals for an Ares 2 policy, invalid UTF-8 and a tab included | never |
| `network_policy.sh` | how a `[connect]` and a `[bind]` section become Landlock port rules, including the cases that are refused, and that the network layer refuses a `[connect]` name rule when the egress broker is off. Port 0 in `[bind]` becomes the ephemeral grant, a udp `[connect]` rule brings the udp grant, and the layer always hands its enforcer `--close-bind`, tells the guard what the policy grants and forwards the operator's minimum Landlock version | never |
| `filesystem_policy.sh` | how the filesystem sections become Landlock path rules: a nested entry narrower than its ancestor is refused as unenforceable, a redundant one and a merely different one are allowed, and the redundant one is what lets an exercise config name that path with fewer rights | never |
| `address_literals.sh` | the spellings of an address, a range and a port in a `[connect]` line: every well-formed IPv4 and IPv6 address, range and port is accepted, and every almost-right one (a short or long dotted quad, a decimal address, a leading zero, a zone, two `::`, a prefix of 0 or past the width, an empty port) is refused as a policy error | never |
| `yaml_subset.sh` | the strict YAML subset an Ares 2 policy may be written in: each accepted construct (block mappings, both sequence indentations, the empty flow collections, both quote styles, comments, a leading `---`, non-ASCII text in valid UTF-8) becomes the exact records, and each construct two YAML readers could read differently (anchors, aliases, tags, block scalars, flow items, a second document, a duplicate key, a tab, a carriage return, a byte order mark, a NUL, invalid UTF-8, a control or bidirectional character in a value, an ambiguous boolean or number, an escape other than `\\` and `\"`, a continuation line) is refused as a policy error naming its line | never |
| `language_configuration.sh` | how a programming language configuration is read: both kinds of `[base]` entry resolve to the base they name, and `environment` (with and without a fallback), `command-ancestor` (through a chain of symbolic links), `fixed` and `password-database home` (the home field of this uid's password database entry, not `HOME`) determine their values; an unknown section or primitive, a value that is not an absolute existing directory, a command not on the `PATH` (one in the current directory included), a variable that is only a shell variable, a `[base]` entry that is absolute, holds `..`, is missing or links out of its folder, a `[connect]` line that is malformed or is not a loopback rule without a port, a password database with no entry for the uid, a home field shorter than two characters (empty or `/`, for which a JVM from version 19 uses `HOME` instead), relative or missing, a control character in the entry or an entry of the wrong number of fields, a configuration with no file, CR, BOM and NUL are refused with file and line, and a `printenv` or `getent` that cannot be run ends the run with PHB-ERUNTIME; a placeholder is determined only when it is used: one whose source cannot be determined does not refuse a run that never uses it and is refused, with the configuration's file and line, once used, one used twice asks its source once, and one the configuration does not name is refused where it was used; every shipped configuration loads | never |
| `shipped_language_configurations.sh` | the eight configurations the image ships, read by the real loader: each Gradle one names exactly the top-level Java base and each Maven one exactly the Maven base under `language-configurations/bases/`, which a run without an Ares 2 policy never folds, and the Maven base grants `[execute]` on no directory that can be written | never |
| `no_language_in_code.sh` | no script, helper or C source under `protecter/src/` outside `protecter/src/config/` names an Ares 2 configuration (`JAVA_USING`) or a Java placeholder (`java.home`, `user.home`, `java.io.tmpdir`), and the same search does find them in the programming language configurations, so it is not vacuous | never |
| `ares_policy.sh` | how an Ares 2 policy becomes the parsed state a `.cfg` gives: every file system flag maps to its sections (`[create-symlink]` with create, `[restructure]` with create and delete), a granted network entry becomes a TCP and a UDP rule for each host shape, milliseconds become seconds exactly and the tightest timeout wins; the refusals are refused with file and line (schema, types, version, placeholders, `*`, `..`, a missing path under each right, all six partial network flag combinations, port 0 beyond loopback, a trailing dot); the shapes of the Ares 2 repository's two example policies are read, the Maven one refused for want of its configuration; a path that reaches the project root through a symbolic link or a name for the root that leads elsewhere is refused, while links that lead away from the root and a root-less run are untouched, and a project root that is `/` or reaches its directory through a link is refused; the covered-entry skip leaves out only a row the base covers through a resolved ancestor; two policies naming different configurations are refused | never |
| `ares_policy_program.sh` | `phobos-policysystem.sh` given an Ares 2 policy: the configuration folds only its own bases and its `[connect]` rows while a `.cfg`-only run still folds every `Base*.cfg` and gets no UDP row, the import merges with a `.cfg` the same in either order, a base row is never removed and a strict-subset `.cfg` row is still refused, the specification of an Ares policy equals that of the hand-written `.cfg` of the same meaning, a non-loopback host with port 0 is refused at its line, the project root comes from `--project-root`, else the tail's last `--chdir`, else nothing, and an empty, relative, missing, `/`, linked or `..` `--project-root` is refused, also through `phobos.sh`, a policy path through a link inside the project root is refused with its file and line while the same through a link outside it is imported, and a misnamed file is refused by both readers | never |
| `seccomp_networksystem.sh` | the connect guard enforces the allow-list by host, port and transport, and refuses what it cannot carry. The transport half is pinned in both directions: a `tcp` rule admits no datagram to the same host and port, and a `udp` rule admits no stream connect to it. A `listen()` is run by the guard on a socket it created: a bound socket listens and its port is free again once closed, an unbound socket is refused, an inherited one is refused, and a thread swapping an unbound socket under the descriptor never creates a listener, with a control without the guard that does. Every datagram connect and send is made by the guard from copies: `sendto`, `sendmsg` and `sendmmsg` arrive intact and `sendmmsg` reports each length, a socket never bound, an inherited one, ancillary data and an oversize datagram are refused, and a thread rewriting the destination while each of the four calls runs never reaches the forbidden receiver, with a control without the guard that does (skipped on a machine where that control never leaks). The guard's resolve mode is run against a stub name server: addresses of both families, an alias, a changed case, a first query that is not answered, the sixteen-address limit, and every refusal (no address, an error, a truncated, malformed, mistaken or missing answer). Through the network layer, a name in a udp rule leads to its own address and a datagram there arrives, another address on the same port is refused, `/etc/hosts` and the specification directory are as they were afterwards, and a resolver that does not answer refuses the run before the command starts | the kernel has no seccomp user-notification, or no C compiler is installed at all; `gcc-14` is preferred and plain `gcc` is used when it is absent; the IPv4-mapped admitting cases skip alone where an IPv6 socket cannot reach 127.0.0.1 |
| `haproxy_conf.sh` | how a `[connect]` section becomes the egress broker's config: a host name becomes a TLS-name allow, an address becomes a destination allow, and everything else is refused. Each name rule tests the port before the TLS name, so a connection to another port is decided without waiting for a ClientHello; where `haproxy` is installed it also checks a generated config parses | never |
| `haproxy_broker.sh` | the egress broker enforces the allow-list by the TLS host name: a connection whose ClientHello names an allowed host reaches the destination, a forbidden one does not; a server that speaks first on a port no name rule names gets its banner to the client at once rather than after the broker's inspect-delay, while a loopback port no rule names stays refused; end to end, the network layer's name mapping and broker are gone once the run has ended; the broker's refusals reach the guard through an anonymous pipe and print one line each (a host name, quoted, or an endpoint), an allowed host prints nothing, the command inherits no descriptor of the pipe and cannot forge a line through the descriptors it holds, the documented limit, that a command with no Landlock domain at all can forge a line through the guard's `/proc` entry, is pinned, and 3000 refusals nobody reads do not stall the broker | a C compiler, `haproxy`, `openssl` or a kernel with seccomp user-notification is absent |
| `haproxy_inbound.sh` | the inbound filter in front of a listener admits only the source addresses an `[accept]` rule names, rejects every other, admits no one for a service with no source, and frees its public port when it stops | a C compiler or `haproxy` is absent |
| `hosts_entries.sh` | the lines a run adds to a hosts file carry its tag and are removed with its specification directory, in place and under a lock, leaving other runs' and the image's lines byte for byte; a failed removal keeps the directory for an outer layer | never |
| `denial_report.sh` | the command's standard error passes through the filesystem layer unchanged and uncounted: words of refusal the command prints itself are no denial, no line starts with `Sandbox denials`, the command keeps its output and its exit status, whether a process it left behind holds the stream or the signal a terminal sends the whole run reaches it and its helpers together, and a Ctrl+C leaves Python's KeyboardInterrupt traceback in the output; these checks need python3 and `/proc` | never |
| `harness_self_test.sh` | the reporting every other suite depends on: a failure is recorded and the suite carries on, `bad` does not end a suite running under `set -e`, the exit status and the printed summary agree, and a skip is counted apart from a pass | never |
| `policy-redundancy-probe.sh` | not a suite and not in CI: it names the entries of a policy that grant Landlock nothing an ancestor already grants, for reading a freshly pruned policy. Those entries are not dead, so it reports and never fails; `AGENTS.md` says what they do. Run it where the policy is applied, since it resolves symbolic links | it is a diagnostic; it answers 0 unless it was called wrongly |

## The repository's command line with a real Docker, run by `build.yml`

`phobos_cli_docker.sh <image>` runs on the host of the `run-phase` job, in the `matrix-b` group, against the
image that job built. Every container it starts is ordinary: `--network none`, and no `--privileged`,
`--cap-add` or `--security-opt`.

| Suite | What it proves |
| --- | --- |
| `phobos_cli_docker.sh` | the file the policy does not name stays refused through `phobos-cli.sh run`, a configuration that names it makes it readable, the exercise is the working directory and writable, the status of the command is the status of `run`, a SIGTERM ends it and the container is gone, the started container has no privilege, capability, security option, device or host namespace, network `none`, memory and process limits and the exercise as its only writable mount, the same command line inside the image applies a configuration and refuses to turn the sandbox off, an Ares 2 policy of the Maven reference exercise passes through the staged copy and the translated project root, and Compose reads what `prune` and `record` build |

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
`--security-opt`, and `--network none`. `protecter/test/integration/landlock-filesystem-and-networksystem-acceptance/README.md` says how to
run them by hand.

| Suite | What it proves |
| --- | --- |
| `run-tests.sh` | the five guarantees: the permitted paths work, the forbidden ones are denied, and the boundary holds for a network endpoint too |
| `extra-tests.sh` | inheritance by a second process, a non-root run, the control probe, and the options no policy file reaches |
| `phase-test.sh` | rights tightened and widened across four phases, and the trap of an unrestricted final phase |
| `shipped-policy-test.sh` | the policy the image actually ships runs a real build; a JVM prints no line for the eleven start-up files the Java base grants file by file, each is readable, a neighbour of each is still refused and reported, and the six refusals the base leaves in place are still refused and reported |
| `maven-policy-test.sh` | the Maven reference exercise passes under the Maven base for each of the four `JAVA_USING_MAVEN_*` configurations, a file the base does not name is refused, and a run with no Ares 2 policy never folds the Maven base |
| `gradle-policy-test.sh` | the Gradle reference exercise passes offline under the Java base the Java image ships (both test cases and the JUnit report), and a canary outside the base's directories, a write beside the working directory and a connection to an unnamed address are refused | never |
| `python-policy-test.sh` | the Python reference exercise passes under the Python base the Python image ships (compileall, then pytest with its JUnit report), and a canary outside the base's directories, a write beside the working directory and a connection to an unnamed address are refused | never |
| `network-port-test.sh` | a raw `connect()` syscall is still refused by Landlock's port rule |
| `scoping-test.sh` | Landlock scoping: a sandboxed process can neither signal a process outside its domain nor reach an abstract UNIX socket there |
| `seccomp-networksystem-test.sh` | the connect guard inside the image: an allowed destination connects, a forbidden one is refused, neither can be redirected, and a rule for one transport admits nothing on the other |

## The protection matrix, run by `build.yml` inside the run-phase image

Twelve suites in `protecter/test/integration/protection-matrix/` hold the whole of `phobos.sh` to what it
promises, each in a step of its own. They run in an ordinary container with `--network none`, plus
`--memory` and `--pids-limit`, which are cgroup caps and not privileges. Every denial has an
unprotected control and a run with only its layer switched off, a check whose control fails is
skipped rather than passed, and a limit the documentation admits is asserted as it is. A skip there
is an open defect, named in the suite's own README, which turns red the moment it is fixed, or a check
that cannot run here and says why: a control the container's seccomp profile blocks, a Landlock version
the kernel lacks, a missing tool or too few processor cores.
`protecter/test/integration/protection-matrix/README.md` says how they are built and what they do not cover.

| Suite | What it proves |
| --- | --- |
| `filesystem.sh` | each filesystem right on its own, what it does not grant, inheritance by children, escape attempts, and the documented gaps; a tree granted by an imported Ares 2 policy, and what the import does not grant |
| `network.sh` | TCP and UDP connect, the destination race, bind and listen closed, `[accept]` filtering, and host names through the egress broker; an imported Ares 2 network entry as TCP and UDP under a programming language configuration, on every kernel |
| `timeout.sh` | a run and everything it started ends at the limit, and no process escapes the group; an imported Ares 2 timeout in milliseconds, not rounded |
| `resources.sh` | every limit is set, read back, enforced, inherited, merged and validated |
| `combinations.sh` | all sixteen subsets of switched-off layers, with one witness per layer in each |
| `cli.sh` | the command line, streams, the environment, overrides, tail flags and odd policy files |
| `lifecycle.sh` | nothing is left behind after any ending of a run, a concurrent command sees none of a run's temporary files in `/tmp`, a process the command leaves behind keeps working through the reporter's drainer, a caller that ignores `SIGCHLD` still gets the command's own status, a signal sent to `phobos.sh` reaches the command, with a documented gap for a command that ignores `SIGTERM` and for `SIGKILL` |
| `policy-syntax.sh` | every shape of a policy line, accepted or refused with its status, and every limit read back from the kernel; Ares 2 policies accepted and refused |
| `network-edge.sh` | range ends, port boundaries, special addresses, IPv6 spellings, socket kinds, a TCP destination rewritten during connect |
| `filesystem-edge.sh` | links, dot-dot, magic links, rights on files and the root, odd names, a link swapped while it is opened |
| `resources-edge.sh` | each limit met through the call that meets it, and the limits Phobos does not set |

## The Python run-phase image, run by the `run-phase-python` job of `build.yml`

The Python run-phase image (`docker/protecter/python/`) is held to every suite above that needs no
Java: `network-port-test.sh`, `bind-port-test.sh`, `scoping-test.sh`, `seccomp-networksystem-test.sh`,
`network-cleanup-test.sh` and the whole protection matrix, in one looped step that names each suite and
fails when any one does. The four acceptance suites that compile Java probes or run Maven
(`run-tests.sh`, `extra-tests.sh`, `phase-test.sh`, `shipped-policy-test.sh`) stay with the Java job.
The pruner's suites on that image are listed in [`pruner/README.md`](../../pruner/README.md).

## The environment variables the suites read

| Variable | Read by | Meaning |
| --- | --- | --- |
| `COMPILER` | the unit runners | the compiler to build the C under test with; `gcc-14` by default |
| `COVERAGE_TOOL` | the unit runners | the gcov that matches that compiler; `gcov-14` by default |
| `PHOBOS_HOME` | the acceptance suites | where Phobos is installed in the image; `/var/tmp/opt/core` by default |
