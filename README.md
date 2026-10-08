# Phobos – Sandboxing for Programming Exercises

## Overview

Phobos is a sandboxing solution for the [Artemis](https://github.com/ls1intum/Artemis) e-learning platform. It runs a student submission for a programming exercise with access to only what the exercise's own tests were shown to need, so a submission cannot read files or reach hosts the exercise never declared. It works in two phases:

- **Resource discovery (pruning), offline.** Phobos runs a reference exercise through the very layers that will grade it, starting from a policy that grants nothing, records every access the layers refuse, grants exactly what each refusal proves, removes what turns out unneeded, and measures the resource limits. The result is a policy per exercise, merged into one base per language: every path the run needs, with the access it needs, and the hosts, ports and limits.
- **Sandbox application, at grading time.** The submission runs confined to that policy. The filesystem is enforced by **Landlock**, a Linux kernel feature that lets an unprivileged process restrict its own access to the filesystem and to TCP ports and then hand that restriction down to everything it starts. Outbound connections are supervised by a **connect guard** that enforces the allow-list by host and port from outside the process; a rule that names a host is enforced by the **egress broker** (an HAProxy that checks the TLS host name) when it is turned on, and a timeout layer bounds the run.

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
  phobos-policysystem.sh   turns the base and exercise configuration into a run's specification
  phobos-filesystem.sh     the filesystem layer, reads the path sets and applies Landlock
  phobos-networksystem.sh  the network layer, runs the connect guard and the egress/inbound HAProxy
  phobos-timeoutsystem.sh  the timeout layer, which applies the group lock when a timeout is set
  phobos-resourcesystem.sh the resource layer, sets the rlimits the policy names, started by the filesystem layer right before Landlock
  phobos-landlock-filesystem-and-networksystem/  its *.c/.h: the C program that applies the Landlock policy, then exec's the command
  phobos-seccomp-networksystem/  its *.c/.h: the connect guard, supervises the egress a command makes and enforces [connect] by host and port
  phobos-seccomp-timeoutsystem/  its *.c: the group lock, a seccomp filter refusing setsid and setpgid, then exec's
  phobos-seccomp-filesystem/     its *.c/.h: the report-only supervisor, reports what Landlock and the group lock block when the network layer is off
  phobos-tools-common/     sourced by every layer through phobos-common.sh, which sources the rest here and the three per-subsystem helpers
    phobos-environment.sh  sourced first by every entry point: PATH and the other lookup variables made safe before anything is looked up
    phobos-common.sh       the shared entry the layers source; it sources the others
    phobos-constants.sh    the numbers the scripts share, named once, the exit statuses among them
    phobos-log.sh          reporting, and counting what a run was denied
    phobos-paths.sh        the two canonical forms a path is compared in
    phobos-time.sh         the timeout contract: how a value is spelled and compared
    phobos-spec-dir.sh     the specification directory and its lifetime
  phobos-tools-policysystem/
    phobos-policy-parse.sh one cfg in, the parsed state and the specification files out
    phobos-policy-yaml.sh  a strict subset of YAML in, flat records with line numbers out
    phobos-language-configuration.sh  a programming language configuration in, its bases, placeholder values and [connect] rows out
    phobos-policy-ares.sh  an Ares 2 security policy in, the same parsed state a cfg gives out
    config_doc.txt         the [connect] and [bind] sections in full: what enforces what
  phobos-tools-filesystem/
    phobos-rights.sh       a parsed policy to the --rights= arguments phobos-landlock-filesystem-and-networksystem takes
  phobos-tools-networksystem/
    phobos-haproxy.sh      the egress broker and inbound filter: turns [connect]/[accept] into an haproxy.cfg
    phobos-network-args.sh [connect] and [bind] to the TCP and UDP port rules Landlock enforces
  config/                  BaseLanguage-<lang>.cfg and TailPhobos.cfg, the shipped policy
    language-configurations/  one file per Ares 2 programming language configuration: its bases, placeholders and [connect] rows
docker/prune_phase/        the layer pruner's image and the orchestrator's
  layers/                  the layer pruner's image: a run-phase image, python3, strace, the probe, an empty base
docker/run_phase/          the images an exercise actually runs in, one per language (java/, python/)
tests/                     the acceptance and probe suites; tests/README.md maps each one to its CI step
var/tmp/                   prune inputs, helpers and example outputs
  helpers/layer_prune/     the layer pruner: observe a run, attribute its refusals, grow, minimise, write a policy
  helpers/layer_record/    the recording pruner: record a program while a person uses it, generate a policy, replay it, compare it
  pruning/orchestrate_core_idea.txt  how the prune containers and the orchestrator share one mount
```

## The filesystem layer: Landlock

`phobos-landlock-filesystem-and-networksystem` is a small C program that reads the path set and, for each path, adds a Landlock rule granting exactly the access the policy allows: read, write, execute, create, delete, ioctl, each as its own right. It then calls `landlock_restrict_self`, after which the process and everything it starts can only lose access, never regain it. There is no mount namespace and no privilege involved; Landlock withholds access to the existing filesystem rather than building a new view of it.

Two consequences of using Landlock rather than a mount sandbox are worth knowing:

- Landlock grants a whole subtree and cannot carve an exception inside it, so a path is either granted, with everything beneath it, or simply not granted. A path that is not granted is denied, but it stays visible by name; there is no way to blank it out.
- A right the running kernel is too old to know is not enforced at all. `phobos-landlock-filesystem-and-networksystem` reports every such gap before the run, and `--minimum-landlock-version` refuses a kernel too old for the guarantee an exercise needs.

## The network layer

Landlock enforces **TCP ports**, so a policy that names a concrete port has that port enforced by the kernel, below anything a submission can do in user space. It covers **UDP ports** only from Landlock version 10 (a udp rule that names a concrete port is refused on an older kernel, unless it is a `[connect]` rule beside a udp loopback rule that names no port, see below), and it does not know hosts, so:

- the **connect guard** (`phobos-seccomp-networksystem`) supervises every `connect()` with a seccomp user-notification and makes an allowed connection itself, so it enforces the `[connect]` allow-list by host and port from outside the process, which a raw system call cannot step around. It holds an IP-literal rule to that exact address and the name `localhost` to the loopback range (every `127.x.x.x` address and `::1`); a rule naming a DNS hostname it cannot tie to an address is held to its port alone, with the host left to the egress broker. A `connect` of another family, such as a UNIX-domain socket, is refused rather than made outside the sandbox. It makes every datagram `connect()`, `sendto()`, `sendmsg()` and `sendmmsg()` itself too, from copies of the address and the data it read out of the command once, so a second thread cannot change a destination after the guard judged it; see SECURITY.md for what that costs.
- the **egress broker** (an HAProxy the network layer starts automatically whenever a `[connect]` rule names a host) enforces that rule by reading the TLS host name from the ClientHello the guard cannot see and, for an exact name, resolving it itself and connecting only to that address. An exact-name rule is refused when no resolver is given, rather than run with a name the broker cannot pin to an address.
- The boundary for external egress, and for UDP and DNS, is the container started with `--network none`. Under it, only loopback exists, and a loopback-only policy needs no port rules; an external host, if one is ever allowed, should name a concrete port so that Landlock can enforce it alongside the guard. Beside a loopback rule that names no port, which the shipped policies carry, a concrete port gets no Landlock rule, because Landlock cannot keep loopback open on every port and close the rest: the connect guard alone enforces it then, by host and port, while the network layer is on, and the run's log says so. For udp that also means the rule does not need Landlock version 10, which a udp rule on its own does.

## How a run is put together

`phobos.sh` builds the run's specification with `phobos-policysystem.sh`, then hands the command down a chain of layers, each of which does its part and starts the rest of the chain: most with `exec`, while the timeout layer runs it under GNU timeout and waits, the connect guard forks it as the child it supervises, and the filesystem layer runs it as a child so it can report the denials afterwards:

```
phobos.sh -> phobos-timeoutsystem.sh -> phobos-networksystem.sh (connect guard) -> phobos-filesystem.sh
          -> phobos-resourcesystem.sh -> phobos-landlock-filesystem-and-networksystem -> the command
```

With the network layer off there is no connect guard, and the filesystem layer puts the report-only supervisor `phobos-seccomp-filesystem` in front of the resource layer and the enforcer, whichever of them is in the chain. It forks before the limits and Landlock exist, so its supervising half is bound by neither, and the half that goes on becomes the rest of the chain.

The base policy is every `Base*.cfg` sitting beside `phobos-policysystem.sh`, applied in sorted order, and the exercise configurations named with `--config` are applied on top. **Ship exactly one `Base*.cfg` per runtime environment.** They are found by a glob and unioned, so a `BasePhobos.cfg` left beside a `BaseLanguage-java.cfg` gives a Java run the paths of every other language as well, which is a wider sandbox that looks like a working one. The prune phase does not prevent that: it writes every applied policy into one directory, the cross-language `BasePhobos.cfg` beside the per-language files, because they are **alternatives** rather than parts of one policy, and choosing between them is the packaging step. `docker/run_phase/java/Dockerfile` does the choosing by naming `BaseLanguage-java.cfg` explicitly, and an image that copied the directory wholesale would ship the union of every alternative. A `BasePhobos.cfg` a run left behind earlier is the same hazard from the other direction, so check what is in that directory rather than what this run wrote. The files meant only for reading go to `debug/` and are never applied at all. With no `Base*.cfg` at all, a run is refused (`PHB-EPOLICY`) rather than run unconfined.

Before any of this, every entry point, `phobos.sh` and each layer started on its own, removes from `PATH` every entry that is not absolute (`.`, any other relative directory, an empty entry, one beginning with `~`), unsets `CDPATH`, and drops whatever is not absolute from `TMPDIR` and from the C library's `GCONV_PATH`, `LOCPATH`, `NLSPATH`, `HOSTALIASES` and `TZDIR`, so that nothing Phobos runs before the sandbox exists is looked up in the current directory, which may be the submission's tree. The command is given the cleaned environment as well (and still no `PATH` when the caller gave none), and a `PATH` with no absolute entry is refused with `PHB-ERUNTIME`. SECURITY.md says why, and what the grader must still keep out of the environment, because it takes effect before a script's first line.

A layer switched off is left out of the chain rather than entered and skipped. Three properties of the chain are relied on and easy to break:

- The resource limits bind the command and nothing beside it. `phobos-resourcesystem.sh` is started by the filesystem layer as the last step before `phobos-landlock-filesystem-and-networksystem`, so the helpers around the command (the filesystem layer's shell, the stderr pass-through and denial counter, the connect guard's supervisor, the report-only supervisor) never run under the command's rlimits. A helper that met the command's file-size, memory or CPU limit would otherwise take the command's output with it.
- The timeout layer waits on the rest of the chain, and the layers below it ignore SIGTERM while their command keeps the default disposition, so the `--kill-after` escalation reaches a command that ignores SIGTERM. The filesystem layer's bounded wait for the denial counts stays below that escalation.
- A run is reported as `PHB-ETIMEOUT` only when GNU timeout's status says so and the run lasted at least its timeout; a command's own 124 or 137, the OOM killer's SIGKILL among them, passes through unchanged.

## Running the pruning phase

The pruning environments are built and run with Compose, one container per language, each writing its result into the shared `var/tmp/path_sets` directory. Every language is pruned by the layer pruner below, on an image built from that language's run-phase image, `phobos-run-phase-java` or `phobos-run-phase-python`, so build those first (`docker/run_phase/<language>/docker-compose.yaml` says how):

```
docker compose -f docker-compose.yaml up --build
```

Each container writes a complete `<lang>_<exercise>.cfg` and its record per exercise. The orchestrator (`docker/prune_phase/orchestrate/orchestrate.py`) holds each `.cfg` to the SHA-256 its record carries, refuses the merge when an exercise was aborted, and then writes `BaseLanguage-<lang>.cfg` (the union of the language's exercises, without limits), the cross-language `BasePhobos.cfg`, `TailPhobos.cfg`, and for each exercise `exercises/<lang>_<exercise>.cfg`, its limits and whatever the base lacks (the base is the union of every exercise, so in practice only the limits), to be passed with `--config`, all under `var/tmp/opt/core/config` of the shared mount. A last container per language, `verify_java` and `verify_python`, runs every exercise once more under exactly that pair and writes its records to `path_sets/verify/`. Copying them over the shipped `core/config/` is a deliberate step of its own: review the result before trusting it, since the allow-list is only as tight as the reference exercises that produced it. Ship exactly one `Base*.cfg` per runtime environment, for the reason above.

Three more files are written into `var/tmp/opt/core/config/debug/` and are never applied. They exist to be read while judging a policy: `BasePhobosIntersect.cfg` names what every language needed, `Base<Lang>Only.cfg` what no other language needed, which is where a policy grows when one language's prune goes wrong, and `Base<Lang>Common.cfg` what every exercise of that language needed: the sections every exercise granted a path, raised as the base is.

### The layer pruner

The layer pruner prunes on the grading layers themselves, so that pruning and grading deny in the same way. It runs the reference exercise through the shipped `phobos.sh`, starting from a policy that grants nothing, records under `strace` (ptrace, no privilege) every call the layers refuse, and grants exactly what each recorded refusal proves: a file it read, a directory it created in, a loopback server it talked to. It then removes every grant two runs show was not needed, measures the limits with margins, verifies the result with every layer on, and proves the forbidden direction with canary files, an unnamed host and port, and a probe that exceeds each limit it can reach (the record lists any limit it could not, and why). Each filesystem and limit check is first made without Phobos, so that only the sandbox's refusal counts. A run that fails without a refusal it can attribute is never turned into a grant; the exercise is aborted instead. Before every layered run the pruner removes whatever earlier runs added outside the working directory, so that each run starts as a fresh grading container would; it therefore runs only in the prune image, which sets `PHOBOS_PRUNE_CONTAINER=1`.

Compose runs it for every language as above. To build the prune image on a run-phase image and prune every exercise under one key by hand, in an ordinary container:

```
docker build --build-arg RUN_PHASE_IMAGE=phobos-run-phase:ci -f docker/prune_phase/layers/Dockerfile -t phobos-prune-layers .
docker run --rm --network none \
  -v "$PWD/var/tmp/testing-dir:/srv/phobos-prune-exercises:ro" -v "$PWD/var/tmp/helpers:/var/tmp/helpers:ro" \
  -v "$PWD/var/tmp/path_sets:/var/tmp/path_sets" phobos-prune-layers \
  python3 /var/tmp/helpers/layer_prune/main.py <key>
```

Each exercise gets `<key>_<exercise>.cfg`, a complete Phobos configuration, and `<key>_<exercise>.json`, the record of every run, every denial with the grant it produced or the reason it produced none, every widening and every containment check. An exercise that aborts gets `<key>_<exercise>.aborted.json` and no configuration. The policy is still only as good as the reference: a code path the reference never took is refused when graded. Exercises that build with Gradle must build without a daemon, since the timeout's group lock refuses the `setsid` a daemon needs, and the memory limit is derived only for an exercise whose `prune.json` declares `"heap_pinned": true`. An exercise that needs an external host declares it in `prune.json` (`"declared_hosts": ["api.example.org:443"]`) and is pruned under the key `java-egress` by the opt-in Compose service `prune_java_egress`, the only layer-pruner service with a network (the recorder's networked service aside): it keeps a declared rule only when the build needs it, drops the others, and aborts on any host nobody declared.

### The Maven prune

The Maven reference exercise, `var/tmp/testing-dir/java-maven/maven-reference/` (Artemis's Maven test template with Ares 2, built offline), is pruned under its own key, `java-maven`, in the same image as Gradle's, by the Compose service `prune_java_maven`, and verified by `verify_java_maven`. The image holds the dependencies it resolves, pre-loaded and held to `docker/run_phase/java/maven-repository.sha256`; `tests/integration/layer_prune_maven.sh` re-hashes every file the manifest lists before it prunes as well. Maven offline stops at the first dependency file it cannot read, so granting that repository file by file would take one prune round per file. Inside a fine-grained root such as `/root` a grant is otherwise always file by file, per-run names aside; Decision 7 of the prune plan makes the exceptions (per-run names, and this one) for a tree whose listed files the image build fixed by checksum. The exercise's `prune.json` declares it, `"pinned_read_roots": [{"path": "/root/.m2/repository", "manifest": "/srv/phobos-manifest/maven-repository.sha256"}]`, strictly (an absolute normalised path strictly beneath a fine-grained root, a manifest directly in `/srv/phobos-manifest`, no field that could name a right), and the pruner re-hashes every listed file by the rule of `pin-repository.sh` before any run and refuses the exercise on a mismatch. A `[read]` of anything beneath it is then granted as that one directory, `[read]` only, never widened to `/root/.m2` or `/root`, with a comment in the policy saying why; every other grant under `/root` is a single file the reference opened or tried to open, writes stay file by file, and no write-class right is granted under `/root/.m2`. This errs wider than the reference for that tree alone: a graded build may read any file in it. The manifest lists what the pre-load added, 59 files; the rest of the tree comes with the digest-pinned base image, and the record counts it. The result is `BaseLanguage-java-maven.cfg` and `exercises/java-maven_maven-reference.cfg` in `var/tmp/opt/core/config`, a base to review and adopt in a pull request of its own that lists every widening.

The build writes scratch files with random names in `/tmp` (Ares, Surefire), which the pruner never grants from a refusal, so the exercise's `prune.json` names the Java seed, `"seed": "java.cfg"`, a file beside the prune image's Dockerfile (`docker/prune_phase/layers/seeds/java.cfg`) that starts the first policy with `[read]`, `[write]`, `[create]` and `[delete]` on `/tmp`, which the shipped Java base grants already (`[read]`, `[write]` and `[restructure]`, which feeds create, delete and refer); the minimisation drops a row the build does not need, and one comment above the path names the seeded rows that stayed. Language-specific rows live only in such a file, never in the pruner or in core. The Gradle reference exercise names the same seed, since any JVM writes there, but no Gradle prune has run on the layers yet, so that is unobserved.

Without the Compose setup, `prune-maven.yml` (started by `workflow_dispatch`) builds both images on amd64 and arm64, runs `tests/integration/layer_prune_maven.sh` in an ordinary container, which prunes, merges and verifies the exercise and shows four wrong reasons aborting (no tests, a version the repository lacks, a manifest that does not match, no seed named), and keeps the policy, its record and the merged base as workflow artefacts.

### The KVM run, a second observer on x86

The container kernels the prune runs on offer Landlock version 8 at most, so they never refuse what versions 9 and 10 add, in particular a UDP bind to an explicit port, and they give no access to Landlock's own audit records. The manual workflow `prune-kvm.yml` therefore takes what the default prune wrote and runs the same layers, in the root file system of the same prune image, on a pinned Linux 7.2 kernel in a QEMU guest under KVM, where the pruner owns the kernel. It runs on x86 runners only (`ubuntu-24.04-arm` has no KVM) in three jobs: the default prune in an ordinary container, the audit observer in the guest, and the orchestrator over both. The observer, `main.py --kernel-observer audit`, writes nothing a prune writes. It proves first, inside the guest, that the kernel offers Landlock version 10 and that one deliberate refusal produces exactly one record it can read, and otherwise ends as indeterminate (status 3), never as a pass. Then, per exercise, it runs one cross-check under the policy with every second grant removed, comparing each Landlock refusal strace attributed with the kernel's record (a mismatch fails the job and means the mapping of A.6.2 is wrong for that call), and verifies the policy on this kernel. The one thing it may add is a `[bind] allow <port> udp` row for a UDP bind the kernel's record names as refused, in `<key>_<exercise>.abi10.cfg`, beside `<key>_<exercise>.abi10.json`, which names the SHA-256 of the `.cfg` it verified and of the sidecar; the orchestrator refuses a record or a sidecar that is not the one it names and writes the rows to `Abi10-<lang>.cfg` and `exercises/<lang>_<exercise>.abi10.cfg`, never into the base, because the enforcer refuses a UDP rule that names a port on a kernel below Landlock version 10 and a base that held one would stop every run of the language there; a host known to have version 10 passes them with `--config`. Any other difference between the two kernels fails the exercise instead. A base generated without such a run is complete up to Landlock version 9 and, on a version 10 kernel, refuses an explicit UDP bind the exercise needs (it fails closed). The enforcer logs what the command is refused only when asked, `PHOBOS_LANDLOCK_LOG_NEW_EXEC=1`, since the kernel otherwise logs only what a process that restricts itself is refused, and the guest sets it. All of this is unproven until the workflow has run to the end. The fixture's audit records under `tests/python/fixtures/audit/` are written in the kernel's documented layout and are replaced by the raw lines the first run uploads (`audit-raw.log`).

### Recording a reference program

The layer pruner needs a reference that runs on its own. For a program that a person uses, a tool clicked through or a REPL typed into, there is the recording pruner, `phobos-record` (`var/tmp/helpers/layer_record/`, in the prune image only). It blocks nothing: the program runs with no sandbox at all under `strace`, with the terminal passed through, and every successful call is recorded. Run it on the instructor's reference program, never on an untrusted submission; `--help` says so first, and so does the header of the policy it writes. Several sessions can be recorded into one recording and merged.

```
RECORD_EXERCISE=<exercise directory> docker compose --profile record run --rm record record --name tool --script /var/tmp/recordings/session.script -- python3 -q
docker compose --profile record run --rm record generate --name tool [--limits] [--memory-pinned]
docker compose --profile record run --rm record check --name tool --script /var/tmp/recordings/session.script -- python3 -q
docker compose --profile record run --rm record diff --name tool --policy /var/tmp/recordings/Base.cfg
```

The recordings are written under `./var/tmp/recordings/<name>` on the host, which the service mounts at `/var/tmp/recordings`; a script and a policy to compare with go there too, since the container sees nothing else of the host but the exercise (`RECORD_EXERCISE`, mounted read-only at `/srv/phobos-record-exercise`) and the helpers. Each `run` is a new container, which is what `check` needs.

`record` copies the exercise into the working directory grading uses (the `--chdir` of `TailPhobos.cfg`), lists every path that exists before the first session of a container, and runs the program there. Without `--script` the terminal is yours; with it the session is typed from a file (`send`, `expect`, `key`, `sleep`). `--sample` also samples the processes, for limits. `generate` turns every session into `policy.cfg` and `record.json` beside them, with the layer pruner's own generalisation (fine-grained roots file by file, per-run names on their smallest stable directory, a created file on the nearest directory that existed before) and a header saying how many sessions it covers. A `[read]` or `[execute]` row never names a path a session created. A file a session created directly in a top-level directory such as `/root` cannot be granted (a grant is never widened to a top-level directory), so `check` reports its creation as a regression; give the program a home in the working directory, as the suites do with `HOME`. Loopback servers become the loopback wildcard, a host the program reached through TLS becomes `allow <name>:<port>` from the ClientHello's host name (and then the policy needs `--resolver`), anything else is held by address with a comment, a datagram connect that sent nothing and a connection that never completed are left out and listed. `record.json` lists every grant with the first calls behind it, every widening with the reason, and every access no policy can grant. `generate` ends with 6 when a successful call was not mapped (`INCOMPLETE` in the header), with 5 when `phobos-policysystem.sh` refuses the policy, and with 4 when a `[read]` or `[execute]` row names a path that did not exist before the sessions.

The policy covers what the sessions did and nothing else: a code path no session took is denied at grading. What grading refuses whatever a policy grants (a connection to a UNIX socket, `setsid`, a device `ioctl`, `io_uring`) is listed at the end of the policy as a comment, never granted. A move between directories gives its source the destination's sections (Landlock refuses it otherwise) except `[execute]`, which never sits beside a write-class right; such a move is listed too. `check` replays a session under `phobos.sh` with the generated policy in a new container and fails on every call that succeeded while recording and is refused now, and on a replay that did not run the session; it verifies that the container starts in the state the recording started in, and says which kind of container it ran in. `diff` lists what a policy lacks for the sessions and what it grants that no session used; it changes nothing, and a base entry an ancestor already covers is marked and never called unused (`AGENTS.md`).

## Running an exercise under Phobos

Build the run-phase image (it compiles the four C products and bakes in the scripts and the shipped policy):

```
.github/scripts/assemble-run-phase-context.sh build/run-phase-context
docker compose -f docker/run_phase/java/docker-compose.yaml up --build
```

For Python exercises, `docker/run_phase/python/docker-compose.yaml` builds the Python run-phase image the same way. It is built from the official Python image (`python:3.13-slim-trixie`), not from Artemis's `ls1tum/artemis-python-docker`, whose release is too old for the C products: an Artemis Python exercise graded under Phobos must select this image. Its CI job holds it to every suite that needs no Java; the acceptance suites that compile Java probes or run Maven stay with the Java image. Its shipped `BaseLanguage-python.cfg` still names the paths of the old Artemis image, so a Python base has to be pruned for it before it grades.

Then, inside that image, wrap the exercise's build command with `phobos.sh`, giving the exercise's own configuration:

```
${PHOBOS_HOME}/phobos.sh --config exercise.cfg -- ./gradlew test
```

`PHOBOS_HOME` is `/var/tmp/opt/core` in the image, and `phobos` on `PATH` is a symbolic link to the same script. The shipped base policy is the `Base*.cfg` the image put beside `phobos-policysystem.sh`, so it is applied without being named. `--config` is for an exercise configuration applied **on top of** that base, never for the base itself: naming a base file there applies it a second time.

**A run given no `--config` is not a grading run.** Without one, Phobos takes its most restrictive shape: every `[connect]`, `[bind]` and `[accept]` rule the base granted is dropped, so the command reaches no network at all, loopback included. The filesystem keeps what the base granted, because a command whose own binary and libraries were denied could not start. A Gradle build talks to its daemon over loopback and therefore fails such a run. A bare `phobos.sh -- <command>` is a containment posture for showing what is denied, not a way to grade.

A bare checkout cannot run this. `phobos-policysystem.sh` finds the base policy by globbing `Base*.cfg` beside itself, and a checkout keeps those files in `core/config/` rather than in `core/`, so a run from one is refused with `PHB-EPOLICY` instead of running unconfined. The image is the delivery vehicle, as it is for the four C products.

The run-phase image is built on Artemis's default Java image, `ls1tum/artemis-maven-template:java25-1` (JDK 25, Maven 3.9.16, Gradle 9.8.0), pinned by digest. It carries the dependencies of two reference exercises under `var/tmp/testing-dir/`, `java/gradle-reference` and `java-maven/maven-reference`, which `pin-repository.sh` checks against `docker/run_phase/java/*-repository.sha256` when the image is built, so that a prune and a grading run read the same bytes and a build is offline. They also show what a Java exercise carries for Phobos. A Gradle wrapper before 9.1.0 cannot run on JDK 25, and a Gradle exercise needs `org.gradle.daemon=false`, a matching `org.gradle.jvmargs` and `org.gradle.internal.instrumentation.agent=false` in its `gradle.properties` and the same heap in `gradlew`, or Gradle forks a daemon whose `setsid` the timeout's group lock refuses.

Run the grading container with **`--network none`** and with cgroup limits (`--memory`, `--pids-limit`, `--cpus`, and a size-bounded `--tmpfs` for scratch). Those are the outer wall Phobos relies on and cannot set for itself.

Start `phobos.sh` without `BASH_ENV`, `LD_LIBRARY_PATH`, `LD_PRELOAD` or `LD_AUDIT`. Those are read before Phobos runs a line, so a relative entry in them, with the submission's tree as the current directory, would hand the submission code that runs before the sandbox exists. SECURITY.md has the details. The interpreter itself is not looked up through `PATH`: every script under `core/` names `/bin/bash` in its `#!` line. A command that relied on `.` in `PATH` must be named by its path, as `./gradlew` is above, since the command is given `PATH` without its relative entries.

stdout carries the command's own output and nothing else. Every message of Phobos itself, the `PHB-EPOLICY`, `PHB-ETIMEOUT`, `PHB-ERUNTIME`, `PHB-ESTATUS` and `PHB-EDENY` reports among them, is written to stderr, and the exit status (11, 14 or 15 for a run Phobos stopped, 16 for a command whose own status could not be read) is the contract a grader should read.

With the network layer off (`-nnr`), or the filesystem layer used on its own, stderr also carries a line for each distinct blocked action the report-only supervisor can attribute with certainty, such as `Phobos Security Error: the program tried to illegally read the File '/etc/shadow' but was blocked by Phobos.`. It covers the refusals of Landlock it can attribute with certainty and, when `phobos.sh`'s timeout layer applies a timeout, the `setsid`, `setpgid` and foreign-ABI calls the timeout's group lock refuses. Every doubt ends in silence, so a run without such a line may still have been refused something. Each path is quoted the way bash quotes it, and a run prints at most 100 such lines. The supervisor never lets a refused call succeed nor a permitted one fail; the one difference it makes is that the group lock's refusals fail with `EACCES` rather than `ENOSYS`. Should it die, the calls it watches fail with `ENOSYS`, so nothing is granted. When the kernel or the setup cannot support it, it prints a notice naming what goes unreported and why, such as `Phobos: filesystem denial reporting is off for this run, because ...`, and the run is enforced all the same. On a kernel older than Linux 6.6 it also says once that it cannot wake synchronously, which only makes reporting slower. With the network layer on, the connect guard is the run's one supervisor and these lines are not printed.

To isolate which layer a failure belongs to, each layer can be turned off on its own:

```
${PHOBOS_HOME}/phobos.sh --no-timeoutsystem-restriction --config exercise.cfg -- <command>
```

Every script here, `phobos.sh` and each layer alike, prints its own manual with `--help` (`-h`), which names every flag it takes, what it reads and which exit statuses it can end with.

`--debug` (`-d`) makes every layer say on stderr what it does and what it runs, and has `phobos-landlock-filesystem-and-networksystem` and the connect guard report verbosely too; the guard then names each destination the allow-list does not name by address and port, for example `refusing connect to a destination the allow-list does not name: [2001:db8::1]:443`. stdout stays the command's own. It prints the whole effective policy, so it is meant for diagnosing a run, not for grading logs. It can only be switched on by the flag, never through the environment.

## Configuration format

A policy is an INI-like file with these sections. Each filesystem section grants exactly its
own right, so a program tree that must be both readable and executable is listed in both
`[read]` and `[execute]`. An unknown section, an unknown key in a limits section, a malformed
`[connect]` line and any content before the first section are refused (PHB-EPOLICY) rather
than ignored, so a typo cannot silently drop a restriction.

The same goes for a path that does not start with `/` (`~`, variables and quotes are not expanded, and a
relative name would depend on the directory the run is started in), Windows line endings, a byte order mark,
a NUL byte, and a number with more than 18 digits (15 digits of seconds for a timeout), which the shell's
arithmetic would read as another number. A path that holds a wildcard (`*`, `?` or `[`) is refused too, since a path is taken as written, and so is a `[read]` or
`[execute]` path in an exercise configuration that does not exist on the system the run is built on, since Landlock can
only anchor a rule on a path that exists and the rule would otherwise grant nothing without a word. A path the command is
meant to create has to be made first, or reached through an existing parent; the sections that change things (`[write]`,
`[create]` and the like) are not asked, because the filesystem layer creates a missing path they name. The shipped base
policies are exempt from the existence check, because they are written to fit more than one image. Each refusal says what is wrong and names the file, and the line wherever one line is at fault.

- `[read]`: one path per line, granted read.
- `[execute]`: one path per line, granted execute. A program tree needs both `[read]` and `[execute]`; a pure data tree needs only `[read]`.
- `[write]`: one path per line, granted write into an existing file (and truncate).
- `[create]`: one path per line, granted the creation of regular files and directories (never device nodes; sockets, named pipes and symbolic links have their own sections below).
- `[create-ipc]`: one path per line, granted the creation of UNIX sockets and named pipes (FIFOs) beneath it, for a tool that needs local IPC objects without also being allowed to create ordinary files.
- `[create-symlink]`: one path per line, granted the creation of symbolic links beneath it. Creating a link is a distinct right a policy opts into; a write through such a link is still resolved and checked by Landlock against the link's target, so the link cannot reach a path the policy does not name.
- `[restructure]`: one path per line, granted create, delete and REFER together, so a tool may create, delete, and rename or move files and directories within the tree. REFER is the right Landlock requires for renaming or linking across directories, and it is granted only here rather than as a side effect of `[create]` plus `[delete]`. A path listed here need not also appear in `[create]` or `[delete]`.
- `[delete]`: one path per line, granted the deletion of files and directories.
- `[connect]`: `allow <host>[:<port>]` lines, the outbound TCP destinations a submission may reach. A host that is exactly one loopback address (`localhost`, one address in 127.0.0.0/8, `::1` in any spelling or its IPv4-mapped form `::ffff:127.x.y.z`, optionally with `/32` or `/128`) may omit the port; a range such as `127.0.0.1/1`, a name such as `127.evil.example` or any other host with no port is refused with the file and the line; an external host must name a concrete port between 1 and 65535, because Landlock enforces ports rather than hosts. Every rule is judged when the specification is built, so a port that does not exist ends the run with PHB-EPOLICY whichever layers are switched on. A host may be written as:
  - an IP literal, `allow 192.0.2.10:443`, which the connect guard holds to that exact address;
  - an IPv4-mapped IPv6 destination, `::ffff:192.0.2.10`, which a program that opens an IPv6 socket to reach an IPv4 peer uses (a Java virtual machine does by default), is the same endpoint as `192.0.2.10` and is judged as that address: a literal IPv4 rule, `localhost` and an IPv4 range cover it exactly as they cover the IPv4 spelling, on the same ports and the same transport, and no rule covers more through it. An IPv6 literal rule still covers only the IPv6 address it names. Landlock enforces ports only, from the socket address's port whatever its family, so its view is unchanged;
  - an address range in CIDR notation, `allow 104.16.0.0/12:443`, for a service whose addresses rotate, such as a content delivery network. An IPv4 range counts its prefix from the IPv4 part, and a range written for an IPv4-mapped IPv6 address needs a prefix of at least 96 bits;
  - a host name, `allow repo.example.org:443`. The guard cannot tie a name to an address before the connection is made, so such a rule is enforced by its port there and by its name by the egress broker, which the network layer starts automatically for a host-name rule; an exact-name rule is refused when no resolver is given;
  - `*`, which names every host and is only meaningful with a port.

  A host name with a star in it, such as `allow *.example.org:443`, is refused with PHB-EPOLICY, whatever the transport. The broker pins an exact name by resolving it itself, which a wildcard name cannot be, so it could only be matched against the name the command presents and would not constrain where the connection goes. Name each host exactly.
  A rule may end with a transport marker, `allow 8.8.8.8:53 udp` or an explicit `tcp`; the marker is optional and defaults to tcp, so every existing rule keeps its meaning. A `udp` rule is enforced for the UDP transport apart from TCP (Landlock `--connect-udp`, the CONNECT_SEND_UDP right, which covers both connecting a datagram socket and sending a datagram), and it needs Landlock version 10, so on an older kernel a udp rule that names a port is refused with exit status 125 from `phobos-landlock-filesystem-and-networksystem`, not with PHB-EPOLICY, rather than left unenforced. A udp rule may also name an exact host, `allow dns.example.org:53 udp`, which has no TLS host name for the egress broker to read. The network layer resolves it **once**, before the command starts, through the resolver given with `--resolver`, and holds the rule to the addresses it had then, at most sixteen; the command is shown the same addresses in `/etc/hosts`, so the two cannot disagree. An address the name gains later is not followed, a name that does not resolve refuses the run, and the lookup needs a networked container. A wildcard name is refused as for TCP. Everything from a `#` to the end of a line is a comment, in every section. An IPv6 address has colons of its own, so a port is written in brackets, `allow [::1]:443`, and a bare `allow ::1` is the host with no port.
- `[bind]`: `allow <port>` lines, the local TCP ports a submission may listen on. **Bind is closed unless a `[bind]` row opens it**: a run with no `[bind]` rule, and a run given no `--config`, cannot bind or listen on any port. A port is enforced by Landlock (`--bind-tcp`) and must be concrete, from 1 to 65535, or `0`, which grants only a port the kernel chooses and no port the submission names; a server that takes whatever port it gets, as Gradle and its workers do, needs `allow 0`, and the shipped Java policy carries it. An explicit port does not open the kernel's own choice, nor the other way round. Landlock's bind right is per-port and cannot narrow to a local address, so a `[bind]` rule takes only a port; a rule that names an address is refused (PHB-EPOLICY). A listener's reachability from outside is governed by `[accept]` and the container's network isolation, not by the bind address. A `[bind]` rule may end with `udp` (Landlock `--bind-udp`), which also needs Landlock version 10; a udp `[connect]` rule additionally grants port 0 for the ephemeral source port the kernel auto-binds to an outgoing datagram. On a kernel below Landlock version 4 (TCP) or 10 (UDP) the bind cannot be closed: Phobos then says so on every run and leaves it open, and `--minimum-landlock-version` in the tail flags turns that into a refusal. An explicit port still refuses a kernel that cannot handle it.
- `[accept]`: `expose <public-port> to <backend-port> from <source>[, <source>...]` lines, which front a submission's TCP listener with an inbound HAProxy that admits only the named source addresses or CIDRs (IPv4 or IPv6) and forwards to the backend port on loopback. It is defence in depth for a networked deployment, not a hard boundary: an `[accept]` rule needs a networked container and therefore gives up the `--network none` default, and the backend is reachable only through the filter as far as the container's network isolation makes it so. The public port must be at or above 1024 and must not be a `[bind]` port; the backend port must be a `[bind]` port, so Landlock keeps the submission off every other port. A rule with no source admits no one. TCP only. See SECURITY.md.
- `[limits]`: `timeout=<seconds>`, the wall-clock bound on the run, and optionally `mem_mb`, `nproc`, `nofile`, `fsize_mb` and `cpu`, applied as rlimits to bound the memory, processes, open files, file size and CPU time the run may use. They are set as the last step before Landlock, so they bind the command and everything it starts, and none of the helpers Phobos runs beside it: the command's output is never cut short because a helper met the command's limit. A value written as `0` switches that limit off. Each key must be named; a bare value is refused.

Every text file is stored with LF line endings: the path sets are read line by line, and a carriage return would become part of a path, so the run would silently lose access the policy granted. `.gitattributes` enforces this.

### Ares 2 policy files

A `--config` file whose name ends in `.yaml` or `.yml` is read as an [Ares 2](https://github.com/ls1intum/Ares2) security policy (version 1), every other one as a Phobos configuration. Each reader refuses the other's format, so a misnamed file is refused, never misread. The YAML is read as a strict subset: anything two YAML readers could read differently (anchors, tags, block scalars, `yes`, `010`, a tab, an escape other than `\\` and `\"`, invalid UTF-8) is refused with its line, and a value that should be text is best quoted.

**The programming language configuration decides the base.** `theFollowingProgrammingLanguageConfigurationIsUsed` names a file `language-configurations/<NAME>.cfg` beside `phobos-policysystem.sh`. It lists the base policies a run under it folds, instead of every `Base*.cfg`, says how each placeholder such as `${java.home}` is determined (`environment`, `command-ancestor`, `fixed` or `password-database home`, each only when a path uses it), and may add loopback `[connect]` rules without a port. This file is the one place a programming language enters Phobos. The image ships the four `JAVA_USING_GRADLE_*` configurations, which name the Java base, and the four `JAVA_USING_MAVEN_*` ones, which name the Maven base `language-configurations/bases/BaseLanguage-java-maven.cfg`, pruned from the Maven reference exercise and never folded by a run without an Ares policy; a configuration with no file is refused, and every Ares policy of a run names the same configuration.

| Ares 2 | Phobos |
| --- | --- |
| `readAllFiles` | `[read]` |
| `overwriteAllFiles` | `[write]` |
| `createAllFiles` | `[create]` and `[create-symlink]`, since Ares counts a symbolic link as created |
| `executeAllFiles` | `[execute]` |
| `deleteAllFiles` | `[delete]` |
| `createAllFiles` with `deleteAllFiles` | `[restructure]` as well, since Ares lets such an entry move files |
| a network entry with all three flags true | a `[connect]` rule for TCP and the same rule with `udp`, `onThePort: 0` meaning every port of loopback |
| a network entry with all three flags false | nothing |
| the tightest `timeout` | `[limits] timeout`, converted from milliseconds exactly, never rounded |

`onThisPathAndAllPathsBelow` is resolved against the project root: `--project-root` where it is given, otherwise the last `--chdir` of the tail flags, otherwise a relative path and `${PROJECT_ROOT}` are refused. That directory must be the one the build tool starts the test JVM in. Refused, with the file and the line: a path of `*`, a backslash, a `..` segment, a placeholder the configuration does not name, a path that does not exist (in every section, since Ares does not say whether a path is a file or a directory), a path that reaches the project root through a symbolic link, or through a name for the root that leads to some other place than the root itself, so that it resolves to somewhere else than it is written (the root usually holds the submission's checkout; a link that leads away from the root, such as `/bin`, stays allowed; a project root that is `/`, reaches its directory through a link or holds a `..` segment is refused; `--project-root` always, the tail's `--chdir` where a path needs it), a network entry that grants only some of its three flags, a host name ending in a dot, a host other than loopback with port 0, a timeout of 0, any version but 1 and any key the schema does not have.

**Phobos adds, Ares narrows.** An imported policy is an exercise configuration, so it is folded on top of the base and can only widen it. An entry the base already grants on the same path or an ancestor, after both are resolved through their symbolic links, is not written, since Landlock would add nothing for it, and the summary line counts it: the narrower intent of such an entry ("this one file, and nothing else") is enforced by Ares inside the JVM, not by Phobos. Each imported file gets one summary line on stderr, which also names what Phobos does not enforce: commands, thread and package entries, and the exemption Ares gives test classes. An imported timeout bounds the whole run, the build tool included, not only the supervised code. A configuration's `allow localhost udp` lets every UDP rule an import brings start on a kernel below Landlock version 10, held by the connect guard alone, and permits UDP to every loopback port for such a run.

## Testing

There is no build system; the shell runs as it is and the C is compiled inside the image. The suites under `tests/` are the checks:

- `tests/unit/`: the Landlock program, the connect guard and the network filter. CI holds the network filter to every line and branch and the connect guard to every line; the Landlock program's suite is measured by weekly mutation testing instead, since coverage instrumentation disturbs the calls it interposes.
- `tests/integration/landlock-filesystem-and-networksystem-acceptance/`: the sandbox applied to real commands in an ordinary container (no `--privileged`, `--cap-add` or `--security-opt`), proving both that a permitted action works and that a forbidden one is denied, and that the shipped policy runs.
- the shell suites under `tests/`: the address cache's port restrictions, the timeout contract, and the prune phase.

`CONTRIBUTING.md` lists the linters, which are the gate, and `AGENTS.md` records the conventions a change here is held to.

## Conclusion

Phobos gives a minimal, reproducible filesystem-and-network boundary for grading untrusted submissions: discover once what an exercise needs, then enforce exactly that at every grading run, with no privilege. Paired with Ares at the JVM level and a locked-down container around it, it lets a grading host run student code with far less trust than running it unconfined. If a submission passes in the sandbox, it did not rely on anything the exercise did not declare.
