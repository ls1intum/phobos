# Phobos – Sandboxing for Programming Exercises

## Overview

Phobos is a sandboxing solution for the [Artemis](https://github.com/ls1intum/Artemis) e-learning platform. It runs a student submission for a programming exercise with access to only what the exercise's own tests were shown to need, so a submission cannot read files or reach hosts the exercise never declared. It works in two phases:

- **Resource discovery (pruning), offline.** Phobos runs a reference exercise repeatedly, hiding one directory at a time and observing whether the tests still pass, to discover the minimal set of files and network hosts the tests actually need. A directory whose absence changes nothing was never needed and stays hidden; one whose absence breaks the run is kept, read-only first and writable only if that is not enough. The result is a *path set*: every path the run needs, with the access mode it needs.
- **Sandbox application, at grading time.** The submission runs confined to that path set. The filesystem is enforced by **Landlock**, a Linux kernel feature that lets an unprivileged process restrict its own access to the filesystem and to TCP ports and then hand that restriction down to everything it starts. Outbound connections are supervised by a **connect guard** that enforces the allow-list by host and port from outside the process, with a preload library (`libnetblocker`) as softer defence in depth beside it, and a timeout layer bounds the run.

The point of the split is that the expensive, fragile part happens once per language environment, offline, and grading itself only applies a fixed configuration.

## Where Phobos sits: three layers, one job each

Phobos is the operating-system layer, and no single layer is the whole story. A submission can be attacked from three angles, and each belongs to a different mechanism:

| Layer | Guards | Mechanism | Covers |
| --- | --- | --- | --- |
| **Ares** | the JVM itself | bytecode/aspect instrumentation | reflection, `Unsafe`, deserialisation, class loading, and other in-process attacks that never touch the OS |
| **Phobos** | the operating system | Landlock (files + TCP ports), `libnetblocker`, a timeout, rlimits | which files a submission may read or write, which TCP ports it may reach, how long it may run and how much memory, how many processes and files it may use |
| **the container** | the machine | `--network none`, cgroup limits | all external network including UDP and DNS, and the hard caps on memory, processes and disk against a fork bomb or a disk-filling run |

Phobos enforces the **filesystem and TCP-port** boundary, filters hosts as defence in depth, bounds the run with a timeout, and applies self-imposed resource limits (rlimits). It does **not** replace Ares (JVM-internal attacks are Ares's job) and it does **not** replace the container's own settings (`--network none` is what closes UDP and external egress; cgroups are the hard resource caps against a fork bomb or a run that fills the disk). The rlimits are an in-process line of defence beside those cgroup caps, not a substitute for them. A grading host is only safe when all three are in place. This division, and the evidence behind it, is set out in [SECURITY.md](SECURITY.md).

Phobos needs **no privileges, no capabilities and no container flags**: Landlock, the preload library and the rlimits are self-imposed by the unprivileged process before it runs the submission. The one thing the container must add is what Phobos cannot do from inside it: start the grading container with no network (`--network none`) and with cgroup limits.

## Repository structure

```
core/                      the sandbox itself
  phobos.sh                entry point: parses the configuration, applies the layers
  phobos-filesystem.sh     the filesystem layer, reads the path sets and applies Landlock
  phobos-network.sh        the network layer, runs the connect guard and drives the preload library
  phobos-resources.sh      the resource layer, sets the rlimits the policy names, started by the filesystem layer right before Landlock
  phobos-timeout.sh        the timeout layer
  phobos-common.sh         shared helpers, sourced by the others
  phobos-constants.sh      the numbers the scripts share, named once, the exit statuses among them
  phobos-landlock*.c/.h    the C program that applies the Landlock policy, then exec's the command
  phobos-connect-guard*.c/.h  the connect guard: supervises connect() and enforces [connect] by host and port;
                           phobos-connect-guard.c is the sequence of stages, the modules beside it do the work
  config/                  BaseLanguage-<lang>.cfg and TailPhobos.cfg, the shipped policy
ld_preloader/              the netblocker sources (the library is built from them in the image)
docker/prune_phase/        one image per language, plus the orchestrator
docker/run_phase/          the image an exercise actually runs in
tests/                     the acceptance and probe suites
var/tmp/                   prune inputs, helpers and example outputs
assets/                    diagrams
```

## The filesystem layer: Landlock

`phobos-landlock` is a small C program that reads the path set and, for each path, adds a Landlock rule granting exactly the access the policy allows: read, write, execute, create, delete, ioctl, each as its own right. It then calls `landlock_restrict_self`, after which the process and everything it starts can only lose access, never regain it. There is no mount namespace and no privilege involved; Landlock withholds access to the existing filesystem rather than building a new view of it.

Two consequences of using Landlock rather than a mount sandbox are worth knowing:

- Landlock grants a whole subtree and cannot carve an exception inside it, so a path is either granted, with everything beneath it, or simply not granted. A path that is not granted is denied, but it stays visible by name; there is no way to blank it out.
- A right the running kernel is too old to know is not enforced at all. `phobos-landlock` reports every such gap before the run, and `--minimum-landlock-version` refuses a kernel too old for the guarantee an exercise needs.

## The network layer

Landlock enforces **TCP ports**, so a policy that names a concrete port has that port enforced by the kernel, below anything a submission can do in user space. Landlock does not know hosts and does not cover UDP, so:

- the **connect guard** (`phobos-connect-guard`) supervises every `connect()` with a seccomp user-notification and makes an allowed connection itself, so it enforces the `[connect]` allow-list by host and port from outside the process, which a raw system call cannot step around. It holds an IP-literal rule (and the name `localhost`) to that exact address; a rule naming a DNS hostname it cannot tie to an address is held to its port alone, with the host left to `libnetblocker`. A `connect` of another family, such as a UNIX-domain socket, is refused rather than made outside the sandbox.
- `libnetblocker`, preloaded through `LD_PRELOAD`, filters by host name and address as **defence in depth** beside the guard. It is bypassable (a raw system call, or a re-exec without `LD_PRELOAD`, steps around it), so it is never the boundary on its own.
- The boundary for external egress, and for UDP and DNS, is the container started with `--network none`. Under it, only loopback exists, and a loopback-only policy needs no port rules; an external host, if one is ever allowed, should name a concrete port so that Landlock can enforce it rather than leaving it to `libnetblocker` alone.

## Running the pruning phase

The pruning environments are built and run with Compose, one container per language, each writing its result into a shared `var/tmp` mount:

```
docker compose -f docker-compose.yaml up --build
```

Each prune container runs the reference exercise for its language under the discovery algorithm and drops a `<lang>` path set into the shared `path_sets` directory. The orchestrator (`docker/prune_phase/orchestrate/orchestrate.py`) then merges the per-exercise results into the shipped `core/config/BaseLanguage-<lang>.cfg` and `TailPhobos.cfg`. Review the result before trusting it: the allow-list is only as tight as the reference exercises that produced it.

## Running an exercise under Phobos

Build the run-phase image (it compiles both C products and bakes in the scripts and the shipped policy):

```
.github/scripts/assemble-run-phase-context.sh build/run-phase-context
docker compose -f docker/run_phase/java/docker-compose.yaml up --build
```

Then wrap the exercise's build command with `phobos.sh`, which applies the shipped base policy plus any per-exercise configuration:

```
core/phobos.sh --config core/config/BaseLanguage-java.cfg -- ./gradlew test
```

Run the grading container with **`--network none`** and with cgroup limits (`--memory`, `--pids-limit`, `--cpus`, and a size-bounded `--tmpfs` for scratch). Those are the outer wall Phobos relies on and cannot set for itself.

stdout carries the command's own output and nothing else. Every message of Phobos itself, the `PHB-EPOLICY`, `PHB-ETIMEOUT`, `PHB-ERUNTIME` and `PHB-EDENY` reports among them, is written to stderr, and the exit status (11, 14 or 15 for a run Phobos stopped) is the contract a grader should read.

To isolate which layer a failure belongs to, each layer can be turned off on its own:

```
core/phobos.sh --no-runtime-restriction --config core/config/BaseLanguage-java.cfg -- <command>
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
- `[create]`: one path per line, granted the creation of files, directories, sockets and named pipes (never device nodes or symbolic links).
- `[delete]`: one path per line, granted the deletion of files and directories.
- `[connect]`: `allow <host>[:<port>]` lines, the outbound TCP destinations a submission may reach. A loopback host may omit the port; an external host should name a concrete port so that Landlock can enforce it. An IPv6 address has colons of its own, so a port is written in brackets, `allow [::1]:443`, and a bare `allow ::1` is the host with no port.
- `[bind]`: `allow <addr>:<port>` or `allow <port>` lines, the local TCP endpoints a submission may listen on. The port is enforced by Landlock (`--bind-tcp`) and must be concrete; the local address is enforced by the libnetblocker bind hook as defence in depth, so a service can be pinned to loopback rather than every interface. A bare port means any local address. An IPv6 address is bracketed, `allow [::1]:8080`.
- `[limits]`: `timeout=<seconds>`, the wall-clock bound on the run, and optionally `mem_mb`, `nproc`, `nofile`, `fsize_mb` and `cpu`, applied as rlimits to bound the memory, processes, open files, file size and CPU time the run may use. They are set as the last step before Landlock, so they bind the command and everything it starts, and none of the helpers Phobos runs beside it: the command's output is never cut short because a helper met the command's limit. A value written as `0` switches that limit off. Each key must be named; a bare value is refused.

Every text file is stored with LF line endings: the path sets are read line by line, and a carriage return would become part of a bind path. `.gitattributes` enforces this.

## Testing

There is no build system; the shell runs as it is and the C is compiled inside the image. The suites under `tests/` are the checks:

- `tests/unit/`: the Landlock program and the network filter, with full line and branch coverage.
- `tests/landlock-acceptance/`: the sandbox applied to real commands in an ordinary container (no `--privileged`, `--cap-add` or `--security-opt`), proving both that a permitted action works and that a forbidden one is denied, and that the shipped policy runs.
- the shell suites under `tests/`: the address cache's port restrictions, the timeout contract, and the prune phase.

`CONTRIBUTING.md` lists the linters, which are the gate, and `AGENTS.md` records the conventions a change here is held to.

## Conclusion

Phobos gives a minimal, reproducible filesystem-and-network boundary for grading untrusted submissions: discover once what an exercise needs, then enforce exactly that at every grading run, with no privilege. Paired with Ares at the JVM level and a locked-down container around it, it lets a grading host run student code with far less trust than running it unconfined. If a submission passes in the sandbox, it did not rely on anything the exercise did not declare.
