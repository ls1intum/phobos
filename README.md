# Phobos – Sandboxing for Programming Exercises

## Overview

Phobos is a sandboxing solution for the [Artemis](https://github.com/ls1intum/Artemis) e-learning platform. It runs a student submission for a programming exercise with access to only what the exercise's own tests were shown to need, so a submission cannot read files or reach hosts the exercise never declared. It works in two phases:

- **Resource discovery (pruning), offline.** Phobos runs a reference exercise repeatedly, hiding one directory at a time and observing whether the tests still pass, to discover the minimal set of files and network hosts the tests actually need. A directory whose absence changes nothing was never needed and stays hidden; one whose absence breaks the run is kept, read-only first and writable only if that is not enough. The result is a *path set*: every path the run needs, with the access mode it needs.
- **Sandbox application, at grading time.** The submission runs confined to that path set. The filesystem is enforced by **Landlock**, a Linux kernel feature that lets an unprivileged process restrict its own access to the filesystem and to TCP ports and then hand that restriction down to everything it starts. Outbound connections are supervised by a **connect guard** that enforces the allow-list by host and port from outside the process; a rule that names a host is enforced by the **egress broker** (an HAProxy that checks the TLS host name) when it is turned on, and a timeout layer bounds the run.

The point of the split is that the expensive, fragile part happens once per language environment, offline, and grading itself only applies a fixed configuration.

## Where Phobos sits: three layers, one job each

Phobos is the operating-system layer, and no single layer is the whole story. A submission can be attacked from three angles, and each belongs to a different mechanism:

| Layer | Guards | Mechanism | Covers |
| --- | --- | --- | --- |
| **Ares** | the JVM itself | bytecode/aspect instrumentation | reflection, `Unsafe`, deserialisation, class loading, and other in-process attacks that never touch the OS |
| **Phobos** | the operating system | Landlock (files + TCP ports), the connect guard, a timeout, rlimits | which files a submission may read or write, which TCP ports it may reach, how long it may run and how much memory, how many processes and files it may use |
| **the container** | the machine | `--network none`, cgroup limits | all external network including UDP and DNS, and the hard caps on memory, processes and disk against a fork bomb or a disk-filling run |

Phobos enforces the **filesystem and TCP-port** boundary, enforces `[connect]` host names through the egress broker when it is turned on, bounds the run with a timeout, and applies self-imposed resource limits (rlimits). It does **not** replace Ares (JVM-internal attacks are Ares's job) and it does **not** replace the container's own settings (`--network none` is what closes UDP and external egress; cgroups are the hard resource caps against a fork bomb or a run that fills the disk). The rlimits are an in-process line of defence beside those cgroup caps, not a substitute for them. A grading host is only safe when all three are in place. This division, and the evidence behind it, is set out in [SECURITY.md](SECURITY.md).

Phobos needs **no privileges, no capabilities and no container flags**: Landlock, the connect guard and the rlimits are self-imposed by the unprivileged process before it runs the submission. The one thing the container must add is what Phobos cannot do from inside it: start the grading container with no network (`--network none`) and with cgroup limits.

## Repository structure

```
core/                      the sandbox itself
  phobos.sh                entry point: parses the configuration, applies the layers
  phobos-policy.sh         turns the base and exercise configuration into a run's specification
  phobos-filesystem.sh     the filesystem layer, reads the path sets and applies Landlock
  phobos-network.sh        the network layer, runs the connect guard and the egress/inbound HAProxy
  phobos-haproxy.sh        the egress broker and inbound filter: turns [connect]/[accept] into an haproxy.cfg
  phobos-resources.sh      the resource layer, sets the rlimits the policy names, started by the filesystem layer right before Landlock
  phobos-timeout.sh        the timeout layer
  phobos-common.sh         the shared helpers, sourced by the others; it sources the seven below
  phobos-log.sh            reporting, and counting what a run was denied
  phobos-paths.sh          the two canonical forms a path is compared in
  phobos-time.sh           the timeout contract: how a value is spelled and compared
  phobos-spec-dir.sh       the specification directory and its lifetime
  phobos-policy-parse.sh   one cfg in, the parsed state and the specification files out
  phobos-rights.sh         a parsed policy to the --rights= arguments phobos-landlock takes
  phobos-network-args.sh   [connect] and [bind] to the TCP port rules Landlock enforces
  phobos-constants.sh      the numbers the scripts share, named once, the exit statuses among them
  phobos-landlock*.c/.h    the C program that applies the Landlock policy, then exec's the command
  phobos-connect-guard*.c/.h  the connect guard: supervises the egress a command makes and enforces [connect] by host and port;
                           phobos-connect-guard.c is the sequence of stages, the modules beside it do the work
  config/                  BaseLanguage-<lang>.cfg and TailPhobos.cfg, the shipped policy
  config_doc.txt           the [connect] and [bind] sections in full: what enforces what
docker/prune_phase/        one image per language, plus the orchestrator
docker/run_phase/          the image an exercise actually runs in
tests/                     the acceptance and probe suites; tests/README.md maps each one to its CI step
var/tmp/                   prune inputs, helpers and example outputs
  pruning/orchestrate_core_idea.txt  how the prune containers and the orchestrator share one mount
```

## The filesystem layer: Landlock

`phobos-landlock` is a small C program that reads the path set and, for each path, adds a Landlock rule granting exactly the access the policy allows: read, write, execute, create, delete, ioctl, each as its own right. It then calls `landlock_restrict_self`, after which the process and everything it starts can only lose access, never regain it. There is no mount namespace and no privilege involved; Landlock withholds access to the existing filesystem rather than building a new view of it.

Two consequences of using Landlock rather than a mount sandbox are worth knowing:

- Landlock grants a whole subtree and cannot carve an exception inside it, so a path is either granted, with everything beneath it, or simply not granted. A path that is not granted is denied, but it stays visible by name; there is no way to blank it out.
- A right the running kernel is too old to know is not enforced at all. `phobos-landlock` reports every such gap before the run, and `--minimum-landlock-version` refuses a kernel too old for the guarantee an exercise needs.

## The network layer

Landlock enforces **TCP ports**, so a policy that names a concrete port has that port enforced by the kernel, below anything a submission can do in user space. Landlock does not know hosts and does not cover UDP, so:

- the **connect guard** (`phobos-connect-guard`) supervises every `connect()` with a seccomp user-notification and makes an allowed connection itself, so it enforces the `[connect]` allow-list by host and port from outside the process, which a raw system call cannot step around. It holds an IP-literal rule (and the name `localhost`) to that exact address; a rule naming a DNS hostname it cannot tie to an address is held to its port alone, with the host left to the egress broker. A `connect` of another family, such as a UNIX-domain socket, is refused rather than made outside the sandbox.
- the **egress broker** (an HAProxy the network layer starts automatically whenever a `[connect]` rule names a host) enforces that rule by reading the TLS host name from the ClientHello the guard cannot see and, for an exact name, resolving it itself and connecting only to that address. An exact-name rule is refused when no resolver is given, rather than run with a name the broker cannot pin to an address.
- The boundary for external egress, and for UDP and DNS, is the container started with `--network none`. Under it, only loopback exists, and a loopback-only policy needs no port rules; an external host, if one is ever allowed, should name a concrete port so that Landlock can enforce it alongside the guard.

## How a run is put together

`phobos.sh` builds the run's specification with `phobos-policy.sh`, then hands the command down a chain of layers, each of which does its part and starts the rest of the chain: most with `exec`, while the timeout layer runs it under GNU timeout and waits, the connect guard forks it as the child it supervises, and the filesystem layer runs it as a child so it can report the denials afterwards:

```
phobos.sh -> phobos-timeout.sh -> phobos-network.sh (connect guard) -> phobos-filesystem.sh
          -> phobos-resources.sh -> phobos-landlock -> the command
```

The base policy is every `Base*.cfg` sitting beside `phobos-policy.sh`, applied in sorted order, and the exercise configurations named with `--config` are applied on top. **Ship exactly one `Base*.cfg` per runtime environment.** They are found by a glob and unioned, so a `BasePhobos.cfg` left beside a `BaseLanguage-java.cfg` gives a Java run the paths of every other language as well, which is a wider sandbox that looks like a working one. The prune phase does not prevent that: it writes every applied policy into one directory, the cross-language `BasePhobos.cfg` beside the per-language files, because they are **alternatives** rather than parts of one policy, and choosing between them is the packaging step. `docker/run_phase/java/Dockerfile` does the choosing by naming `BaseLanguage-java.cfg` explicitly, and an image that copied the directory wholesale would ship the union of every alternative. A `BasePhobos.cfg` a run left behind earlier is the same hazard from the other direction, so check what is in that directory rather than what this run wrote. The files meant only for reading go to `debug/` and are never applied at all. With no `Base*.cfg` at all, a run is refused (`PHB-EPOLICY`) rather than run unconfined.

A layer switched off is left out of the chain rather than entered and skipped. Three properties of the chain are relied on and easy to break:

- The resource limits bind the command and nothing beside it. `phobos-resources.sh` is started by the filesystem layer as the last step before `phobos-landlock`, so the helpers around the command (the filesystem layer's shell, the stderr pass-through and denial counter, the connect guard's supervisor) never run under the command's rlimits. A helper that met the command's file-size, memory or CPU limit would otherwise take the command's output with it.
- The timeout layer waits on the rest of the chain, and the layers below it ignore SIGTERM while their command keeps the default disposition, so the `--kill-after` escalation reaches a command that ignores SIGTERM. The filesystem layer's bounded wait for the denial counts stays below that escalation.
- A run is reported as `PHB-ETIMEOUT` only when GNU timeout's status says so and the run lasted at least its timeout; a command's own 124 or 137, the OOM killer's SIGKILL among them, passes through unchanged.

## Running the pruning phase

The pruning environments are built and run with Compose, one container per language, each writing its result into a shared `var/tmp` mount:

```
docker compose -f docker-compose.yaml up --build
```

Each prune container runs the reference exercise for its language under the discovery algorithm and drops a `<lang>` path set into the shared `path_sets` directory. The orchestrator (`docker/prune_phase/orchestrate/orchestrate.py`) then merges the per-exercise results into `BaseLanguage-<lang>.cfg`, the cross-language `BasePhobos.cfg` and `TailPhobos.cfg` under `var/tmp/opt/core/config` of the shared mount. Copying them over the shipped `core/config/` is a deliberate step of its own: review the result before trusting it, since the allow-list is only as tight as the reference exercises that produced it. Ship exactly one `Base*.cfg` per runtime environment, for the reason above.

Three more files are written into `var/tmp/opt/core/config/debug/` and are never applied. They exist to be read while judging a policy: `BasePhobosIntersect.cfg` names what every language needed, `Base<Lang>Only.cfg` what no other language needed, which is where a policy grows when one language's prune goes wrong, and `Base<Lang>Common.cfg` what every exercise of that language needed with the same right.

Pruning and grading do not deny in the same way. While pruning, a hidden directory is an empty, writable tmpfs, because Landlock cannot make a path look empty; while grading, a path the policy does not name is refused with `EACCES`. A tool that only needs some writable scratch directory can therefore pass its prune with that directory hidden and still be refused when graded, which is worth checking first when a freshly pruned policy fails a run that passed its prune.

## Running an exercise under Phobos

Build the run-phase image (it compiles both C products and bakes in the scripts and the shipped policy):

```
.github/scripts/assemble-run-phase-context.sh build/run-phase-context
docker compose -f docker/run_phase/java/docker-compose.yaml up --build
```

Then, inside that image, wrap the exercise's build command with `phobos.sh`. The shipped base policy is the `Base*.cfg` the image put beside `phobos-policy.sh`, so it is applied without being named:

```
${PHOBOS_HOME}/phobos.sh -- ./gradlew test
```

`PHOBOS_HOME` is `/var/tmp/opt/core` in the image, and `phobos` on `PATH` is a symbolic link to the same script. `--config` is for an exercise configuration applied **on top of** that base, never for the base itself: naming a base file there applies it a second time.

A bare checkout cannot run this. `phobos-policy.sh` finds the base policy by globbing `Base*.cfg` beside itself, and a checkout keeps those files in `core/config/` rather than in `core/`, so a run from one is refused with `PHB-EPOLICY` instead of running unconfined. The image is the delivery vehicle, as it is for the three C products.

Run the grading container with **`--network none`** and with cgroup limits (`--memory`, `--pids-limit`, `--cpus`, and a size-bounded `--tmpfs` for scratch). Those are the outer wall Phobos relies on and cannot set for itself.

stdout carries the command's own output and nothing else. Every message of Phobos itself, the `PHB-EPOLICY`, `PHB-ETIMEOUT`, `PHB-ERUNTIME` and `PHB-EDENY` reports among them, is written to stderr, and the exit status (11, 14 or 15 for a run Phobos stopped) is the contract a grader should read.

To isolate which layer a failure belongs to, each layer can be turned off on its own:

```
${PHOBOS_HOME}/phobos.sh --no-runtime-restriction -- <command>
```

`--debug` makes every layer say on stderr what it does and what it runs, and has `phobos-landlock` and the connect guard report verbosely too; stdout stays the command's own. It prints the whole effective policy, so it is meant for diagnosing a run, not for grading logs. It can only be switched on by the flag, never through the environment.

## Configuration format

A policy is an INI-like file with these sections. Each filesystem section grants exactly its
own right, so a program tree that must be both readable and executable is listed in both
`[read]` and `[execute]`. An unknown section, an unknown key in a limits section, a malformed
`[connect]` line and any content before the first section are refused (PHB-EPOLICY) rather
than ignored, so a typo cannot silently drop a restriction.

- `[read]`: one path per line, granted read.
- `[execute]`: one path per line, granted execute. A program tree needs both `[read]` and `[execute]`; a pure data tree needs only `[read]`.
- `[write]`: one path per line, granted write into an existing file (and truncate).
- `[create]`: one path per line, granted the creation of regular files and directories (never device nodes; sockets, named pipes and symbolic links have their own sections below).
- `[create-ipc]`: one path per line, granted the creation of UNIX sockets and named pipes (FIFOs) beneath it, for a tool that needs local IPC objects without also being allowed to create ordinary files.
- `[create-symlink]`: one path per line, granted the creation of symbolic links beneath it. Creating a link is a distinct right a policy opts into; a write through such a link is still resolved and checked by Landlock against the link's target, so the link cannot reach a path the policy does not name.
- `[restructure]`: one path per line, granted create, delete and REFER together, so a tool may create, delete, and rename or move files and directories within the tree. REFER is the right Landlock requires for renaming or linking across directories, and it is granted only here rather than as a side effect of `[create]` plus `[delete]`. A path listed here need not also appear in `[create]` or `[delete]`.
- `[delete]`: one path per line, granted the deletion of files and directories.
- `[connect]`: `allow <host>[:<port>]` lines, the outbound TCP destinations a submission may reach. A loopback host may omit the port; an external host must name a concrete port between 1 and 65535, because Landlock enforces ports rather than hosts. Every rule is judged when the specification is built, so a port that does not exist ends the run with PHB-EPOLICY whichever layers are switched on. A host may be written as:
  - an IP literal, `allow 192.0.2.10:443`, which the connect guard holds to that exact address;
  - an address range in CIDR notation, `allow 104.16.0.0/12:443`, for a service whose addresses rotate, such as a content delivery network. An IPv4 range counts its prefix from the IPv4 part, and a range written for an IPv4-mapped IPv6 address needs a prefix of at least 96 bits;
  - a host name, `allow repo.example.org:443`. The guard cannot tie a name to an address before the connection is made, so such a rule is enforced by its port there and by its name by the egress broker, which the network layer starts automatically for a host-name rule; an exact-name rule is refused when no resolver is given;
  - a name with a leading wildcard label, `allow *.example.org:443`, which the broker matches by suffix (a suffix routes by the TLS host name to the header's destination and does not itself constrain the onward address);
  - `*`, which names every host and is only meaningful with a port.
  Everything from a `#` to the end of a line is a comment, in every section. An IPv6 address has colons of its own, so a port is written in brackets, `allow [::1]:443`, and a bare `allow ::1` is the host with no port.
- `[bind]`: `allow <port>` lines, the local TCP ports a submission may listen on. The port is enforced by Landlock (`--bind-tcp`) and must be concrete. Landlock's bind right is per-port and cannot narrow to a local address, so a `[bind]` rule takes only a port; a rule that names an address is refused (PHB-EPOLICY). A listener's reachability from outside is governed by `[accept]` and the container's network isolation, not by the bind address.
- `[accept]`: `expose <public-port> to <backend-port> from <source>[, <source>...]` lines, which front a submission's TCP listener with an inbound HAProxy that admits only the named source addresses or CIDRs (IPv4 or IPv6) and forwards to the backend port on loopback. It is defence in depth for a networked deployment, not a hard boundary: an `[accept]` rule needs a networked container and therefore gives up the `--network none` default, and the backend is reachable only through the filter as far as the container's network isolation makes it so. The public port must be at or above 1024 and must not be a `[bind]` port; the backend port must be a `[bind]` port, so Landlock keeps the submission off every other port. A rule with no source admits no one. TCP only. See SECURITY.md.
- `[limits]`: `timeout=<seconds>`, the wall-clock bound on the run, and optionally `mem_mb`, `nproc`, `nofile`, `fsize_mb` and `cpu`, applied as rlimits to bound the memory, processes, open files, file size and CPU time the run may use. They are set as the last step before Landlock, so they bind the command and everything it starts, and none of the helpers Phobos runs beside it: the command's output is never cut short because a helper met the command's limit. A value written as `0` switches that limit off. Each key must be named; a bare value is refused.

Every text file is stored with LF line endings: the path sets are read line by line, and a carriage return would become part of a path, so the run would silently lose access the policy granted. `.gitattributes` enforces this.

## Testing

There is no build system; the shell runs as it is and the C is compiled inside the image. The suites under `tests/` are the checks:

- `tests/unit/`: the Landlock program, the connect guard and the network filter. CI holds the network filter to every line and branch and the connect guard to every line; the Landlock program's suite is measured by weekly mutation testing instead, since coverage instrumentation disturbs the calls it interposes.
- `tests/landlock-acceptance/`: the sandbox applied to real commands in an ordinary container (no `--privileged`, `--cap-add` or `--security-opt`), proving both that a permitted action works and that a forbidden one is denied, and that the shipped policy runs.
- the shell suites under `tests/`: the address cache's port restrictions, the timeout contract, and the prune phase.

`CONTRIBUTING.md` lists the linters, which are the gate, and `AGENTS.md` records the conventions a change here is held to.

## Conclusion

Phobos gives a minimal, reproducible filesystem-and-network boundary for grading untrusted submissions: discover once what an exercise needs, then enforce exactly that at every grading run, with no privilege. Paired with Ares at the JVM level and a locked-down container around it, it lets a grading host run student code with far less trust than running it unconfined. If a submission passes in the sandbox, it did not rely on anything the exercise did not declare.
