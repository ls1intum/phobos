# Prune on the Layers Implementation Plan

> **How to execute:** work through Part B one task at a time, test first, with a review between tasks. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Bubblewrap pruner with one that derives a Phobos policy (filesystem, network, timeout and resource limits) by running the reference exercise under the very layers a grading run uses, starting from "deny everything" and granting only what an observed, attributed denial proves necessary.

**Architecture:** A Python pruner runs inside a prune image built `FROM` the run-phase image, so every run goes through the shipped `phobos.sh` chain unchanged. Each observed run is wrapped in `strace`, an unprivileged ptrace observer that records every system call the layers refused, with its path or address, operation and errno. A grow loop grants exactly what the record attributes to a layer, a minimisation pass removes grants that were not needed, the limits are measured with a margin, and the result is written as Phobos configuration and checked by the real policy parser and by repeated unobserved runs.

**Tech Stack:** Python 3 (standard library only), bash, `strace` from the distribution archive, the existing `phobos.sh` layers and C enforcers, Docker, pytest for unit tests, the repository's shell harness for integration tests.

**Spec:** Part A of this document. The request, the research and the design live here rather than in a separate file because the plan pull request is meant to carry exactly one file; Part B (the tasks) argues from Part A.

## Global Constraints

- British English in all prose, comments, messages, workflow and step names.
- No em dashes anywhere; prefer a comma, a full stop or brackets over a hyphen.
- One variable, field or function declaration per line, in every language (no `a, b = ...`, no `int x, y;`).
- Every text file LF, final newline, no trailing whitespace outside Markdown, spaces not tabs.
- No `--privileged`, `--cap-add` or `--security-opt` for any suite or for the prune container itself.
- Never add a bind, a capability or an allowed host to make a test pass.
- A grant needs an attributed denial; a run that fails without one is never turned into a grant.
- The pruner never changes `core/` behaviour for a grading run; adopting a regenerated base policy into `core/config/` is a separate, reviewed pull request that states "this now permits X, which it did not permit before" for every widening.
- Generated configuration must be accepted by `core/phobos-policysystem.sh` as it stands on `main` (absolute paths, no wildcard characters `*`, `?`, `[`, existing `[read]`/`[execute]` paths in an exercise configuration, no nested entry whose rights are a strict subset of an ancestor's).
- Python code is linted by `ruff check --no-cache .` and, under `var/tmp/helpers`, by `bandit --recursive --ini .bandit --severity-level medium`; shell by `shellcheck -x -S warning`; Dockerfiles by `hadolint --config .hadolint.yaml`; YAML by `yamllint --strict .`; everything by `ec --no-color`.
- Branch names use an allowed prefix (`feature/`, `ci/`, `docs/`, not `feat/`).

---

# Part A: Design

## A.1 The request

Markus asked (translated from German): "Currently the pruning runs on Bubblewrap. I want the pruning to run on the tools the layers actually use today, and the pruning to include network, timeout and resources as well. My idea: is there a way to record blocked file access or network access on the console? Then we could first restrict everything and then, run by run, release one part of the tree or one network address, until a run passes without a block. Would that be an idea?"

## A.2 What the pruner does today, and why it has to change

`var/tmp/pruning/detect_minimal_fs.sh` walks the filesystem top down. Each candidate directory is hidden behind an empty tmpfs in Bubblewrap (`--tmpfs`), the build is run, and the directory is kept hidden (`n`), bound read-only (`r`) or bound writable (`w`) depending on which state lets the build still succeed. `run_minimal_fs_all.sh` runs it per exercise, `var/tmp/helpers/emit_artifacts.py` turns the bindings into `.paths`/`.json`, `make_lang_sets.py` forms union and intersection, and `docker/prune_phase/orchestrate/orchestrate.py` writes `BaseLanguage-<lang>.cfg`, `BasePhobos.cfg` and `TailPhobos.cfg`.

Five problems follow from that design:

1. **It measures a different sandbox from the one that grades.** A hidden directory is an empty, writable tmpfs; a path the grading policy does not name is refused with `EACCES`. CLAUDE.md and README.md both warn that a prune can pass and grading can then fail. A tool that only needs "some writable scratch directory" passes the prune with that directory hidden.
2. **It only measures the filesystem, and only three states.** Landlock grants nine rights per path (r, w, x, m, p, l, f, d, i), and the network, timeout and resource layers are not measured at all. `orchestrate.py` writes `[read]`, `[execute]`, `[write]`, `[create]`, `[delete]` and a fixed loopback `[connect]`; the shipped `BaseLanguage-java.cfg` has since gained `[restructure]`, `[create-ipc]` and `[bind] allow 0`/`allow 0 udp` that no prune produced.
3. **It is a blind search.** It does not know which path a build needed; it hides one directory after another and runs the whole build each time, one to three runs per visited directory.
4. **It cannot see a fixed rule of the layers.** Bubblewrap does not refuse `setsid`, does not refuse an `AF_UNIX` `connect` through the connect guard, and does not apply rlimits, so an incompatibility between an exercise and the grading layers (for example a Gradle daemon that needs `setsid`, which the timeout's group lock refuses) is invisible until grading.
5. **Its output format has drifted** from what `phobos-policysystem.sh` reads and refuses since PRs 158 and 159 (relative paths, wildcards, missing `[read]`/`[execute]` paths in an exercise configuration, CRLF).

## A.3 Research: can a denial be observed and attributed without privileges?

The constraint is AGENTS.md's: an ordinary container, no `--privileged`, no `--cap-add`, no `--security-opt`. Each candidate below states what it can attribute (path, operation, right, host and port) and what privilege it needs.

### A.3.1 Landlock audit logging

- **What it is.** Since Linux 6.15 (the Landlock audit series merged for v6.15-rc1, with the `LANDLOCK_RESTRICT_SELF_LOG_*` flags as ABI 7) a Landlock denial is emitted through the kernel audit subsystem as an `AUDIT_LANDLOCK_ACCESS` record, and domain lifecycles as `AUDIT_LANDLOCK_DOMAIN`. A filesystem record carries the blocking domain, the missing rights and the object, for example `domain=195ba459b blockers=fs.make_reg,fs.refer path="/usr/local" dev="vda2" ino=365`; network blockers are `net.bind_tcp`, `net.connect_tcp` and, from ABI 10, `net.bind_udp`, `net.connect_send_udp`; scope blockers are `scope.abstract_unix_socket` and `scope.signal`. Denials of a self-sandboxed program are logged by default when audit is enabled.
- **Attribution.** The best of all candidates: the kernel names the exact missing right (`blockers=`) and the object (path for the filesystem; the port for the network). It does not name a remote host, because Landlock does not know hosts.
- **What it needs.** A record has to be read from the audit netlink socket's read-only multicast group `AUDIT_NLGRP_READLOG`, which requires `CAP_AUDIT_READ` in the initial user namespace and is delivered through the initial network namespace only; without an audit daemon the records fall back to the kernel log, which needs `/dev/kmsg` or `syslog(2)` and `CAP_SYSLOG` under `dmesg_restrict`. Audit is not namespaced.
- **Measured here** (Docker 29.8.1, kernel 7.0.14-linuxkit aarch64, Landlock ABI 8, ordinary container with `--network none`, as root and as uid 65534): binding the audit netlink socket to `AUDIT_NLGRP_READLOG` fails with `EPERM`; `/dev/kmsg` does not exist; `syslog(SYSLOG_ACTION_READ_ALL)` fails with `EPERM`.
- **Verdict.** Not usable inside an ordinary container. It becomes usable where the pruner owns the kernel, for example in a KVM guest (see PR 161, which asks whether hosted runners can boot one); that is recorded as open question Q6 and as a later, optional second observer, never as the default.

### A.3.2 The Landlock "quiet" flag (ABI 10)

ABI 10 adds `LANDLOCK_ADD_RULE_QUIET` and the ruleset fields `quiet_access_fs`, `quiet_access_net` and `quiet_scoped`, which suppress audit records for chosen objects and rights. It only filters audit output; it does not make a denial observable to anyone who cannot already read audit. It would help an audit-based observer drop known-harmless denials, so it belongs with A.3.1 and Q6. The CI kernels (6.17 and 7.0) offer ABI 7 and 8; ABI 10 needs 7.2.

### A.3.3 seccomp user notification on `open`, `openat`, `execve` and the rest

- **What it is.** The mechanism the connect guard already uses: a filter returns `SECCOMP_RET_USER_NOTIF`, a supervisor reads the arguments and answers.
- **Attribution.** The supervisor sees the call and its arguments before the kernel runs it, never the result. To know whether Landlock would refuse the call it would have to reimplement Landlock's path-beneath semantics in user space (symbolic links, `openat2` resolve flags, descriptor-relative paths, mounts, the right that each flag combination needs), and every divergence would turn into a wrong grant or a missed one. Used to decide (a "complain mode" that allows everything and records it) it replaces the real enforcer with a model of it, which is exactly what this redesign removes.
- **What it needs.** No privilege, only `no_new_privs`. But only one listener is allowed in a filter tree: a second `SECCOMP_FILTER_FLAG_NEW_LISTENER` fails with `EBUSY` when an ancestor filter already has one (`has_duplicate_listener` in `kernel/seccomp.c`), and the connect guard's filter is that ancestor. A nested-listener flag (`SECCOMP_FILTER_FLAG_ALLOW_NESTED_LISTENERS`) exists only as a patch series (v3, December 2025) and cannot be assumed on the runners.
- **Verdict.** Rejected as the observer.

### A.3.4 fanotify

Permission events (`FAN_OPEN_PERM`, `FAN_ACCESS_PERM`) and mount or filesystem marks need `CAP_SYS_ADMIN`. Unprivileged fanotify (since 5.13) is limited to notification events on inode marks with FID reporting. fanotify reports accesses that happen, not accesses an LSM refused, and knows nothing of the network. Rejected.

### A.3.5 ptrace, through `strace`

- **What it is.** A tracer follows the command and every descendant and sees each system call's entry (number and arguments) and exit (return value and errno), so it sees the kernel's actual answer, Landlock's `EACCES` and `EXDEV`, the connect guard's `EACCES`, the group lock's `EPERM`, and an rlimit's `EMFILE`, `EAGAIN` or `ENOMEM`.
- **Attribution.** Path as passed (plus the directory descriptor), operation and its flags, errno, and for socket calls the decoded address and port; the right is derived from the call and its flags (A.6.2). It does not say which layer answered; that is inferred from the call (a socket call refused with `EACCES` is the guard or Landlock's port rule; a path call refused with `EACCES` or `EXDEV` is Landlock or a DAC or AppArmor refusal, told apart by a control replay, A.6.3).
- **What it needs.** No capability for tracing one's own descendants. YAMA `ptrace_scope` 0 or 1 permits it (3 forbids all ptrace); Docker's default seccomp profile allows `ptrace` on kernels 4.8 and newer. Landlock only stops a sandboxed process from tracing a less sandboxed one; a tracer outside every domain may trace into one.
- **Measured here**, same container as above:
  - a hand-written tracer (`PTRACE_TRACEME`, `PTRACE_SYSCALL`) observed a Landlocked child's `openat("/etc/hostname") = -13 EACCES`, as root and as uid 65534;
  - a follow-forks tracer (`PTRACE_O_TRACEFORK|VFORK|CLONE|EXEC`, `PTRACE_GET_SYSCALL_INFO`) around the real chain in the image `phobos-run-phase:ci`, `phobos.sh --config <cfg allowing 127.0.0.1:*> -- bash -c 'cat /var/log/dpkg.log; cat /etc/hostname; exec 3<>/dev/tcp/10.0.0.1/80'`, recorded `openat /var/log/dpkg.log errno=EACCES` (Landlock), `connect 10.0.0.1:80 errno=EACCES` (connect guard), `openat /dev/tty errno=EACCES` and several `AF_UNIX` `connect` refusals (the guard refusing a UNIX-domain connect), while `/etc/hostname` succeeded and the run completed with status 0. The chain's seccomp listener, the group lock and Landlock all kept working under the tracer.
  - The same run's denial counter printed `Sandbox denials: network=0, filesystem=3`, although one of the three "filesystem" lines was the connect guard's network refusal. That is the heuristic of A.3.8 in action.
  - Of the 116 failed system calls recorded in that run, 9 were `EACCES` or `EPERM`; the rest were ordinary `ENOENT` (the `PATH` search), `ENOTDIR` and `ENXIO`, and many came from the layers' own shells before the command started. Attribution therefore has to filter by errno and by process (A.6.1).
- **Verdict.** Chosen as the observer. `strace` is used rather than a new tracer because it decodes every system call of both architectures (x86_64 still has the legacy `open`, `creat`, `mkdir`, `unlink`, `rename` calls that aarch64 lacks) and every socket address; Q1 asks whether Markus prefers a dedicated C tracer instead.

### A.3.6 `LD_PRELOAD`

PR 114 removed libnetblocker, the `LD_PRELOAD` network filter, because a library preloaded into a process is stepped around by a raw system call, a static binary or a re-exec, so it was never the boundary. For observation the same holes become blind spots: the Phobos enforcers themselves are static PIE, a JVM issues some calls directly, and a wrapper of libc functions sees what the program asked for, not what the kernel refused. A blind spot turns into a run that fails "without a denial", which the pruner must not turn into a grant. Rejected.

### A.3.7 eBPF and the BPF LSM

Attaching to LSM hooks needs `CAP_BPF` with `CAP_PERFMON` or `CAP_SYS_ADMIN`, a kernel booted with `lsm=...,bpf`, and Docker's default seccomp profile blocks `bpf(2)`. Rejected.

### A.3.8 Parsing the command's own stderr

What `count_denials` in `core/phobos-tools-common/phobos-log.sh` does: it counts lines matching `Permission denied|EACCES|EROFS` and `EAI_AGAIN|EAI_FAIL|EAI_NONAME|Network is unreachable|Connection timed out`. It never sees a denial the program swallowed, counts a message as often as the program prints it, cannot tell a network refusal that says "Permission denied" from a filesystem one (measured above), and depends on the program's wording and locale. It is a report, never a status, and it stays that. Rejected as a source of grants.

### A.3.9 Summary

| Mechanism | Path | Operation | Right | Host and port | Privilege | Ordinary container |
| --- | --- | --- | --- | --- | --- | --- |
| Landlock audit | yes | yes | exact | port only | `CAP_AUDIT_READ` in the initial namespaces | no (measured `EPERM`) |
| Landlock quiet flag | filters audit only | | | | as audit | no |
| seccomp notify | before the call only | yes | modelled | yes | none, but `EBUSY` beside the guard | no |
| fanotify | successful accesses | partly | no | no | `CAP_SYS_ADMIN` for permission events | no |
| ptrace (`strace`) | yes | yes | derived | yes | none (`ptrace_scope` at most 1) | yes (measured) |
| `LD_PRELOAD` | libc calls only | yes | derived | yes | none | yes, with blind spots |
| eBPF / BPF LSM | yes | yes | exact | yes | `CAP_BPF`, `lsm=bpf` | no |
| stderr parsing | sometimes | no | no | no | none | yes, heuristic |

Runner Landlock ABIs: the CI kernels are 6.17 (ABI 7) and 7.0 (ABI 8); the local Docker Desktop kernel 7.0.14 reports ABI 8. `RESOLVE_UNIX` (ABI 9) and the UDP rights (ABI 10, kernel 7.2) are therefore never observed on today's runners (Q6).

## A.4 "Would that be an idea?"

**Yes, with two changes.** Recording blocked accesses on the console is possible without privileges, through ptrace, and "deny everything, then release step by step" is the right direction, because every grant then rests on a denial the grading layers actually produced. The two changes: the record names the exact path or address, so the pruner jumps straight to it instead of searching the tree, and it releases every attributed denial of a run at once and afterwards removes the grants that were not needed, because "until a run passes without a block" would also grant every harmless probe a tool makes (a file it tries and does without), which is a wider sandbox that still looks right.

Trade-offs, honestly:

- **Fewer, cheaper runs.** The old pruner runs the whole build once to three times per visited directory, hundreds of builds for a JDK tree. The new loop converges in a handful of grow runs, most of which fail fast, plus a bounded minimisation budget.
- **The same sandbox.** Every verdict is taken under the grading layers, so "the prune passed, grading failed" stops being a known gap; a failure that remains is a nondeterministic build or a code path the reference never took.
- **Tighter rights.** A denial names the right (read, write, create, delete, refer, ipc, symlink, execute), so a path gets that right and no blanket `w`.
- **New coverage.** Network rules, bind ports and limits are derived instead of hand-written, and an incompatibility with a fixed rule (setsid, UNIX-domain connect, raw sockets, device ioctl) is reported instead of hidden.
- **Costs.** ptrace slows a system-call-heavy build (measured in PR 3; observed runs only, the verdict runs are untraced), ptrace must be available on the host (`ptrace_scope` at most 1), `strace` joins the prune image (not the grading image), and generalising an observed file to its directory errs permissive by design (A.7).

## A.5 Approaches considered

1. **Deny first, grow from denials, then minimise (chosen).** Start from an empty allow-list, run under the real layers with the observer, grant every attributed denial, repeat until the verdict matches the reference, then remove unneeded grants by delta debugging with unobserved runs. Every grant is justified by a real denial; nothing in the pruner models Landlock.
2. **Learning run, then minimise.** One permissive run records every access (successful or not), the policy is built from all of them, then minimised. One run instead of several, but it records accesses Landlock never gates (`stat`, `access`), so the pruner would need its own model of which accesses Landlock checks, and the initial set is far larger, which moves the work into minimisation. Kept as a possible accelerator (seed the grow loop) if grow runs turn out to dominate; not built now (YAGNI).
3. **Keep the top-down hide search and swap Bubblewrap for Landlock.** Landlock cannot hide a path; "hide" would become "deny", the walk stays blind and the run count stays in the hundreds. Rejected: it keeps problem 3 and only half solves problem 1.

## A.6 Chosen architecture

### A.6.1 Components

```
prune image  = FROM run-phase image  +  strace  +  python3  +  BasePrune.cfg (grants nothing)
                                       (the grading image itself is unchanged)

var/tmp/helpers/layer_prune/           Python package, standard library only
  record.py        Syscall, Denial, the JSONL record format
  strace_parse.py  strace -f output -> Syscall stream, process tree, in-domain pids
  attribute.py     Syscall -> Denial (layer, operation, object, right), fixed-rule refusals
  control.py       control replays outside the sandbox: is a refusal Landlock's?
  generalise.py    Denial -> grant (path, sections), compaction, hierarchy normalisation
  cfgfile.py       grants + network rules + limits -> Phobos .cfg text, and its checks
  network.py       network denials -> [connect] / [bind] rules
  limits.py        samples -> measurements -> [limits] with margins; which limit ended a run
  sampler.py       /proc sampling of the run's process tree
  verdict.py       a run's outcome: exit class, per-test results, NO-SOURCE, infra failure
  runner.py        one run through phobos.sh, with or without the observer and sampler
  search.py        grow loop and ddmin
  stages.py        the per-exercise pipeline: baseline, filesystem, network, limits, verification
  main.py          per-language entry point, writes the artefacts

docker/prune_phase/layers/Dockerfile   the prune image
docker/prune_phase/orchestrate/        stays; merges .cfg artefacts instead of .paths
```

Without a mount namespace the exercise has to run at the path grading uses, `/var/tmp/testing-dir`, so its sources cannot live there too, as they do for the Bubblewrap pruner (which bound a copy over that path). The prune container therefore mounts the exercise sources read-only at `/srv/phobos-prune-exercises/<lang>/<exercise>` (from `./var/tmp/testing-dir`), the helpers read-only at `/var/tmp/helpers`, and only `./var/tmp/path_sets` read-write at `/var/tmp/path_sets`; `/var/tmp/testing-dir` is local to the container and is replaced by a fresh copy of the exercise before every run.

The observer is the outermost process: `strace -f ... phobos.sh --config <candidate> -- <build script>`. It therefore also traces the layers' own shells and helpers. Only processes inside the Landlock domain count: a process is in the domain once its own `landlock_restrict_self(...) = 0` has been recorded, and every process cloned from an in-domain process afterwards is too. Network refusals are attributed under the same rule, which drops the guard's refusals of the filesystem layer's own helper shells (measured in A.3.5).

### A.6.2 Mapping a refused call to a right

Landlock checks a creation, a removal and a rename on the parent directory, and a read, write, truncate or execute on the object itself. The pruner maps as follows; letters are the enforcer's, sections are the configuration's.

| Refused call (errno) | Object | Right | Section |
| --- | --- | --- | --- |
| `open`/`openat`/`openat2` without `O_CREAT`, access mode read, regular file | the file | `read_file` | `[read]` |
| same on a directory, or `getdents64` on a descriptor of one | the directory | `read_dir` | `[read]` |
| `open*` with write or read-write access on an existing file | the file | `write_file` (+ `read_file` for read-write) | `[write]` (+ `[read]`) |
| `open*` with `O_TRUNC`, `truncate`, `ftruncate` on an existing file | the file | `truncate` | `[write]` |
| `open*` with `O_CREAT` on a path that did not exist | parent directory | `make_reg` | `[create]` |
| `mkdir`, `mkdirat` | parent directory | `make_dir` | `[create]` |
| `mknod`/`mknodat` of a FIFO, `bind` of a pathname `AF_UNIX` socket | parent directory | `make_fifo`/`make_sock` | `[create-ipc]` |
| `symlink`, `symlinkat` | parent directory | `make_sym` | `[create-symlink]` |
| `unlink`, `unlinkat`, `rmdir` | parent directory | `remove_file`/`remove_dir` | `[delete]` |
| `rename*`, `link*` across directories (`EXDEV` on one filesystem) | both parent directories | `refer` (+ make/remove) | `[restructure]` |
| `rename*` within one directory | the directory | make + remove | `[create]` + `[delete]` |
| `execve`, `execveat` (`EACCES`) | the binary, then its `PT_INTERP` or `#!` interpreter | `execute` | `[execute]` (+ `[read]`) |
| `ioctl` on a device (`EACCES`) | the device | `ioctl_dev` | none: no section grants it, reported as fixed |
| `mknod` of a block or character device | | | none: never granted, reported as fixed |
| `connect` of `AF_INET`/`AF_INET6` (`EACCES`) | destination | guard or `connect_tcp` | `[connect]` (A.6.5) |
| `sendto`/`sendmsg`/`sendmmsg` (`EACCES`) | destination | guard or `connect_send_udp` | `[connect] ... udp` |
| `bind` of `AF_INET`/`AF_INET6` (`EACCES`) | local port | `bind_tcp`/`bind_udp` | `[bind]` |
| `listen` (`EACCES`) on a socket bound to no port | | ephemeral listen | `[bind] allow 0` |
| `connect` of `AF_UNIX` (`EACCES`) | | the guard refuses the family | none: fixed |
| `socket` of `AF_PACKET`, raw, ICMP (`EACCES`) | | the guard refuses the kind | none: fixed |
| `setsid`, `setpgid` (`EPERM`) | | the timeout's group lock or the guard | none: fixed |
| any path call (`EPERM`) | | the container's seccomp profile, a mount restriction, Landlock's ban on `mount` | none: other |

An `execve` refused with `EACCES` is ambiguous between the binary, its ELF interpreter and a script's interpreter; the pruner grants `execute` (and `read`) on the binary and resolves `PT_INTERP` (read from the ELF header) or the `#!` line itself, adding the interpreter in the same round. `rename` gets `[restructure]` only when the two parents share `st_dev`; otherwise `EXDEV` is the filesystem's own answer and nothing is granted.

### A.6.3 Telling a Landlock refusal from any other refusal (control replay)

The command runs as the same uid as the pruner and under the same AppArmor profile, so a refusal Landlock did not cause also happens outside the sandbox. For each candidate denial the pruner replays the access itself, outside every Landlock domain:

- read: `os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)` then close; a directory with `O_DIRECTORY`;
- write on an existing regular file: `os.open(path, os.O_WRONLY | os.O_NONBLOCK)` without `O_TRUNC`, then close (FIFOs and device nodes are never replayed and are classified as fixed);
- create in a parent: `tempfile.mkstemp(dir=parent)` then `os.unlink` (the prune container is disposable, so a changed directory mtime is acceptable);
- execute: `os.access(path, os.X_OK)` and the file's mode;
- refer: compare `os.stat(...).st_dev` of the two parents.

A replay that also fails means the refusal was not Landlock's, and granting would not help: the denial is recorded as `layer="other"` and never granted. Network refusals need no replay: the guard and Landlock's port rules are the only producers of `EACCES` on `connect`, `sendto` and `bind` in the prune container.

Two further rules keep a foreign refusal from becoming a grant:

- **Errno by layer.** Landlock answers a filesystem refusal with `EACCES` (and `EXDEV` for a missing `refer`); an `EPERM` on a path call comes from elsewhere (the container's seccomp profile, a mount restriction, Landlock's own ban on `mount` inside a domain) and is classified `other`, never granted. `EPERM` on `setsid`/`setpgid` is the group lock's or the guard's and is `fixed`.
- **A grant must take effect.** After a round's grants, the next observed run must no longer show the same call refused on the same object. A refusal that survives its own grant was not caused by the missing right: the grant is withdrawn, the denial reclassified `other`, and the exercise aborts with that evidence rather than looping.

### A.6.4 The algorithm

```
prune_exercise(exercise, budget):
    reference = None
    for attempt in 1..3:                                   # B1: unsandboxed baseline
        run = run_direct(exercise)
        require run.verdict.tests_ran and not run.verdict.no_source and not run.verdict.infra_failure
        if reference is None: reference = run.verdict
        require same_outcome(run.verdict, reference)        # otherwise: abort "flaky reference"

    permissive = permissive_policy()                         # B2: layers on, everything granted
    run = run_layers(permissive, observe=True, limits=OFF)
    if not same_outcome(run.verdict, reference):
        abort("incompatible with a fixed rule of the layers", fixed_refusals(run))

    # stage 1: filesystem, network layer off, limits off
    fs = {}
    for round in 1..budget.grow_rounds:
        run = run_layers(fs, observe=True, network=OFF, limits=OFF)
        denials = [d for d in attribute(run.trace) if d.layer == "filesystem" and landlock_caused(d)]
        if same_outcome(run.verdict, reference):
            break                                            # remaining denials were harmless; reported, not granted
        if not denials:
            rerun = run_layers(fs, observe=False, network=OFF, limits=OFF)
            if same_outcome(rerun.verdict, reference): continue
            abort("failed without an attributable denial", run)
        fs = fs | generalise(denials, snapshot)
    else: abort("did not converge within the grow budget")
    fs = normalise_hierarchy(compact(fs))
    fs = ddmin_minimise(fs, test=lambda g: same_outcome(run_layers(g, observe=False, network=OFF, limits=OFF).verdict, reference),
                        budget=budget.minimise_runs)

    # stage 2: network, filesystem fixed, limits off
    net = NetworkRules.empty()
    for round in 1..budget.network_rounds:
        run = run_layers(fs, net, observe=True, limits=OFF)
        if same_outcome(run.verdict, reference): break
        decision = network_rules(attribute(run.trace), bound_ports(run.trace), exercise.declared_hosts)
        if decision.refused_external: abort("needs external network", decision.refused_external)
        if decision.adds_nothing_to(net): abort("network stage failed without an attributable denial", run)
        net = net | decision
    net = ddmin_minimise_network(net, ...)

    # stage 3: limits
    samples = [run_layers(fs, net, observe=False, limits=OFF, sample=True) for _ in 1..3]
    require all(same_outcome(s.verdict, reference) for s in samples)
    limits = margins(measure(samples), budget.margins)
    for attempt in 1..3:
        runs = [run_layers(fs, net, limits, observe=False) for _ in 1..budget.verification_runs]
        if all(same_outcome(r.verdict, reference) for r in runs): break
        signature = limit_signature(failed run, its samples, limits)
        if signature is None: abort("failed under limits without a limit signature")
        limits[signature] = raise_limit(limits[signature])
    else: abort("limits did not settle")

    # stage 4: joint verification, unobserved, every layer on, exactly as grading
    runs = [run_layers(fs, net, limits, observe=False) for _ in 1..budget.verification_runs]
    if not all(same_outcome(r.verdict, reference) for r in runs):
        diagnose once with observe=True; route a filesystem or network denial back to its stage (at most 2 rounds); otherwise abort
    write <lang>_<exercise>.cfg and <lang>_<exercise>.json
```

`abort` never writes a configuration for the exercise; the orchestrator refuses to merge a language with a missing exercise, as it does today.

Every candidate configuration passes the **acceptance gate** before it is run or written: `cfgfile.render` refuses what the parser would refuse (A.6.5, Task 5.2), and `phobos-policysystem.sh --spec-dir <temporary> --config <candidate>` must then build a specification from it with status 0. A run that Phobos itself stopped before or around the command is never a verdict: it is a defect of the pruner and aborts the exercise, because reading it as "the policy is too narrow" would turn a malformed candidate into more grants. The status alone cannot say so, since `phobos.sh` passes the command's own status through and a build may well end with `2` (as `make` does) or `125`; a run counts as stopped by Phobos when its status is `2`, `11`, `15` or `125` (`PHB_EXIT_USAGE`, `PHB_EPOLICY`, `PHB_ERUNTIME`, `PHB_ENFORCER_REFUSED_EXIT` in `phobos-constants.sh`) **and** its stderr carries Phobos's own marker for it (the usage text, `(PHB-EPOLICY)`, `(PHB-ERUNTIME)`, or a refusal line prefixed `[phobos-landlock-filesystem-and-networksystem]`, `[phobos-seccomp-networksystem]` or `[phobos-seccomp-timeoutsystem]`). The connect guard prints its verbose refusals under the same prefix while a run goes on normally, so only a line that precedes the command's start (no in-domain `execve` of the build script yet, or for an unobserved run, before the first line the build script prints) counts. `14` (`PHB-ETIMEOUT`) is a verdict, the timeout class, as `verdict.read_verdict` records it.

The final stage also runs **containment checks** with the protection matrix's `probe.c` under the final configuration, so every generated configuration is proven in both directions, not only by its passing build: a canary file the pruner creates before the first run at `/srv/phobos-prune-canary/secret` and at `/root/phobos-prune-canary`, which no reference touches, must be refused for read; writing into a path the configuration grants only `[read]` must be refused; `connect` to `10.0.0.1:80` and `bind` to port 8080 must be refused unless the configuration names them; and a probe that exceeds each derived limit must be refused or ended. A containment check that passes (the canary is readable) aborts the exercise.

Default budget: `grow_rounds=40`, `network_rounds=10`, `minimise_runs=150`, `verification_runs=3`. A minimisation that exhausts its budget keeps the remaining grants (errs permissive) and says so in the record.

### A.6.5 Per-layer derivation

**Filesystem.**

- *Nearest existing ancestor, not the exact path, and not the blind subtree.* A refused object that existed before the run is granted on its own path when it lies under a fine-grained root (default `/etc`, `/dev`, `/proc`, `/sys`, `/root`, `/home`, `/run`), and on its containing directory otherwise; a directory object is granted on itself. An object the run itself created (absent from the pre-run snapshot of the exercise and write paths) is granted on the nearest ancestor that existed before the run, because the next run creates a differently named temporary file and because an exercise configuration may only name existing `[read]`/`[execute]` paths. Creation, removal and rename are granted on the parent directory, which is what Landlock checks anyway.
- *Write-class rights are never widened beyond what Landlock checks.* `[write]` is granted on the file itself, and `[create]`, `[create-ipc]`, `[create-symlink]`, `[delete]` and `[restructure]` on the directory Landlock checks them on (the parent, or for an object the run created, the nearest pre-existing ancestor). Only `[read]` and `[execute]` are ever generalised to a containing directory or compacted.
- *Compaction.* When at least `k=3` children of a directory hold identical `[read]`/`[execute]` rights, and the directory is not a fine-grained root and not at depth below 2, the children are replaced by the directory. Never `/`.
- *Every widening is visible.* For each generalisation and each compaction the record lists the observed objects that caused it and the number of existing entries the wider grant newly covers beyond them, so a reviewer of the generated policy sees exactly where it is wider than the observation. A sibling cannot be "proven denied" under a directory grant, since a directory grant covers its siblings by construction; the protection is the restriction to read-class rights outside fine-grained roots, the review of this list, and Q7.
- *Hierarchy normalisation.* A nested entry whose rights are a strict subset of an ancestor's would be refused by `resolve_rights_hierarchy`. Such an entry is raised to its ancestor's rights rather than dropped: Landlock already grants those rights there, so enforcement does not change, and an exercise configuration that names that exact path keeps folding onto it (AGENTS.md, "A base entry an ancestor already covers is not dead code").
- *Rights minimisation.* ddmin works on (path, section) pairs, so a path granted `[read]` and `[write]` can lose `[write]` alone.
- *Canonical paths.* Every grant is written as `os.path.realpath` of the object (Landlock anchors on the inode, and a changeable rule on a symbolic link is refused by the enforcer). A path holding `*`, `?`, `[` or a newline cannot be written; it is generalised to its parent and reported.

**Network.**

- The record of a refused `connect`, `sendto`, `sendmsg`, `sendmmsg`, `bind` or `listen` carries family, address, port and the socket type (from the preceding `socket` call on that descriptor), so transport is known.
- *Loopback.* A refused loopback destination whose port was bound by a process of the same run (a recorded successful `bind`/`listen` plus `getsockname`) is a server the run started on a port the kernel chose, which differs per run: it becomes `allow 127.0.0.1:*` or `allow [::1]` or, for both families, `allow localhost`. A loopback destination on a port nobody in the run bound becomes an exact `allow 127.0.0.1:<port>` and is reported, since nothing in a prune container listens there.
- *Bind.* A `bind` refused on port 0, or a `listen` refused on an unbound socket, becomes `allow 0` (with `udp` for a datagram socket). A refused explicit port becomes `allow <port>` only when it is a loopback service the exercise's own tests start; otherwise it is reported.
- *External destinations are never granted from an address.* The prune container runs `--network none` (AGENTS.md: a prune must not reach the network for anything it did not intend, pin what a probe build resolves). A refused external destination aborts the exercise ("needs external network") unless the exercise's manifest declares the host. A record holds addresses, not names: libc resolves the name before `connect`, and reversing an address (a CDN, a rotating pool) does not give back the name the exercise meant.
- *Why a name rule needs a resolver.* The connect guard cannot tie a name to an address, so it holds a name rule to its port; the egress broker (HAProxy) holds it to the name by reading the TLS host name, and for an exact name it resolves the name itself and connects only to the result. Without a resolver it could not pin the name, and the rule would only constrain the port, so `phobos-networksystem.sh` refuses an exact-name rule without `--resolver`. A `udp` name has no TLS host name at all; the network layer resolves it once before the command starts and writes the addresses into `/etc/hosts` (`config_doc.txt`). A declared host is therefore emitted as `allow <name>:<port>` and verified in a networked prune container started with `--resolver`; it is never derived from a `--network none` run. That networked verification is a separate, opt-in compose service (`prune_java_egress`), run only for exercises whose `prune.json` declares hosts, with dependency versions pinned and its own output directory; it can only confirm or refuse the declared rules, it never adds a rule of its own, and the default prune services stay `network_mode: none`.
- *DNS.* A refused `sendto` to port 53 means the exercise resolves names; under `--network none` it is reported with the declared-host rule above, never granted as an address.
- *`[accept]`* (inbound filtering) cannot be observed in a prune run, which has no outside client; it is never emitted and stays hand-written.

**Timeout and resources.**

- *Measure with every limit off*, under the final filesystem and network policy, three unobserved runs with the sampler. `[limits]` with `timeout=0` and each limit `0` switches them off (README, `[limits]`).
- *Sampler.* The pruner makes itself a child subreaper (`prctl(PR_SET_CHILD_SUBREAPER)` through `ctypes`) so that daemons the build leaves behind are reparented to it and their final accounting is not lost, and it samples `/proc` every 100 ms for every descendant: `VmPeak` (address space, what `ulimit -v` bounds per process), `utime+stime` per process (what `ulimit -t` bounds per process), the highest open descriptor number (what `ulimit -n` bounds), and the number of tasks owned by the run's uid (what `ulimit -u` bounds, per real uid and counting threads). After the run it records the largest file under the write grants (what `ulimit -f` bounds per file) and the wall-clock time.
- *Margins* (each configurable, defaults chosen to err permissive, Q3): `timeout = max(60, ceil_to(3 x wall, 30))`, `cpu = max(30, ceil_to(3 x max per-process cpu, 10))`, `mem_mb = max(512, ceil_to(1.5 x max VmPeak, 256))`, `nproc = max(64, 2 x max tasks + 16)`, `nofile = max(256, 2 x (max descriptor + 1))`, `fsize_mb = max(16, ceil_to(2 x largest file, 16))`.
- *Exit statuses are evidence, never proof.* A command can end with `137` or `153` of its own accord, and `phobos-timeoutsystem.sh` passes a command's own `124` or `137` through unchanged. A limit is therefore only raised when all of these hold: the same policy with that limit switched off passed (the measurement runs), the failing run's signature below matches, and the raised value then passes. A raise doubles the value, at most three times; a limit still failing after that aborts the exercise. Nothing in this stage grants access, it only moves a bound that the measurement already placed.
- *Which limit ended a run* (pinned by the protection matrix, `resources.sh` and `resources-edge.sh`): status `14` is the timeout (`PHB-ETIMEOUT`); status `153` is `SIGXFSZ`, the file size; status `137` is `SIGKILL`, which is the CPU limit (the kernel kills at the hard limit, and `ulimit -t` sets soft and hard alike) when the last sample of some process's CPU time was within one second of `cpu`, and otherwise the container's cgroup OOM killer, which is not a Phobos limit and aborts the exercise; `EMFILE` from `open`, `socket`, `pipe`, `dup` is `nofile`; `EAGAIN` from `clone`, `clone3`, `fork` is `nproc`; `ENOMEM` from `mmap`, `brk`, `clone` is `mem_mb`. The last three are read from a diagnostic observed run and only count when they do not also appear in the run with the limits off (a JVM probes large reservations and falls back on its own).
- *Base versus exercise.* Limits are merged by "the largest value wins", so a limit in a base configuration is a floor for every exercise. Derived limits are therefore written into the per-exercise configuration only; the base keeps the built-in defaults.
- *uid.* `RLIMIT_NPROC` does not apply to uid 0 in the initial user namespace. The pruner measures and verifies as the uid grading uses, and records it.

### A.6.6 Order

Filesystem first with the network layer and the limits off, then network with the filesystem fixed, then limits under both, then everything together. Each stage then has one layer that can deny, which keeps attribution unambiguous and keeps a limit from cutting a run short while the filesystem is still being discovered. The joint verification is the only run shape that matters for grading, and a denial found there is routed back to the stage that owns it.

### A.6.7 Stopping criteria

- grow: the verdict equals the reference; denials that remain in a passing run are harmless and reported, never granted;
- abort: a failure without an attributable denial after one unobserved rerun, a grow, network or limit budget exhausted, a flaky baseline, an incompatible fixed rule, an external destination not declared;
- minimisation: every grant tried once, or the budget spent;
- done: `verification_runs` consecutive unobserved runs under the final policy with every layer on, all equal to the reference.

### A.6.8 Exercise inputs, and the Maven reference exercise

Every exercise the pruner takes meets one contract, read by `runner.Exercise` (Task 4.2):

- it is a directory `var/tmp/testing-dir/<key>/<exercise>/`, mounted read-only at `/srv/phobos-prune-exercises/<key>/<exercise>` (A.6.1), and copied afresh to `/var/tmp/testing-dir` before every run;
- it holds an executable `build_script` or `build_script.sh`, which the runner starts with `bash` in `/var/tmp/testing-dir`, and optionally `prune.json` with `report_globs` and `declared_hosts`;
- its committed copy matches none of its report globs, so a stale report can never stand in for a run (the runner refuses such an exercise before the baseline);
- every dependency its build resolves is pinned and present in the image before the run, so that under `--network none` a fetch is not a variable (AGENTS.md).

`<key>` is the language argument of `main.py` and of the orchestrator's `--langs`, and the orchestrator unions every exercise of one key into `BaseLanguage-<key>.cfg`. A key therefore stands for one base: a build tool whose base must stay apart gets a key of its own.

The **Maven reference exercise** is the first real input beyond the integration fixture. It is defined once, in the Ares 2 import plan of pull request 163 (`docs/superpowers/plans/2026-10-05-ares2-policy-import.md`, section A.4.3: location, contents, pinned versions, the offline build and its measurements), and is not repeated here; this plan relies only on the contract above and on the exercise's place, `var/tmp/testing-dir/java-maven/maven-reference/` (key `java-maven`), which that plan's pull request 5 creates. Task 8.4 prunes it, and the resulting `BaseLanguage-java-maven.cfg` is what that plan's pull request 6 adopts as its Maven base. That adoption is the separate, reviewed pull request the Global Constraints ask for, and it states every widening.

## A.7 Which direction each heuristic errs in

AGENTS.md asks for this for every heuristic.

| Heuristic | Errs | Why that direction |
| --- | --- | --- |
| Granting every attributed denial of a failing run at once | permissive, corrected by minimisation | converges in few runs; minimisation removes what was not needed |
| Leaving denials of a passing run ungranted | restrictive | grading denies them too, and the reference still passed |
| Directory instead of file outside fine-grained roots, `[read]`/`[execute]` only | permissive (siblings, read-class only) | a student's solution may read a sibling the reference did not; per-file grants would fail it; write-class rights are never widened |
| Nearest pre-existing ancestor for objects the run creates | permissive (siblings) | temporary names differ per run, and only existing paths may be named |
| Compaction at `k=3` children | permissive | robustness against code paths the reference did not take |
| Raising a strict-subset nested entry | neutral for enforcement | Landlock already grants those rights there |
| Minimisation accepting a removal after one passing run | restrictive if a run passed by luck | caught by the final verification runs, which restore the pre-minimisation grants and report "minimisation unstable" |
| Loopback port generalised to `*` when the run bound it | permissive within loopback only | the port differs per run; loopback is the shipped policy's existing shape |
| Margins on every limit | permissive | a correct but slower solution must not be cut short; the cgroup caps stay the outer wall |
| CPU attribution of a `137` by the last sample | restrictive if sampling missed the peak | the next attempt raises the limit, at most three times, then aborts |
| A run that fails without an attributable denial | never granted | the AGENTS.md rule this design exists to honour |

## A.8 Keeping a wrong-reason failure out of the allow-list

1. **The verdict is not an exit status.** It is the exit class plus the per-test outcomes from the JUnit XML reports (`build/test-results/**/*.xml`, `target/surefire-reports/*.xml`, or a glob from the exercise's `prune.json`), plus the existing patterns: `NO-SOURCE` (Gradle reports it with status 0), `INFRA_FAILURE_PATTERNS` from `detect_minimal_fs.sh`. Two runs agree only when the same tests ran with the same outcomes. Maven has the same trap in two spellings, measured in the run-phase image (Maven 3.9.11, Surefire 3.5.3): a project without tests ends with status 0, `[INFO] No tests to run.` and no report, and `-DskipTests` ends with status 0 and `[INFO] Tests are skipped.`. Both lines set `no_source`, as `NO-SOURCE` does. The Maven reference exercise also passes `-DfailIfNoTests=true`, which turns the first into status 1 and `No tests to run!`, but that only adds a failing status; the verdict still comes from the reports, and a run with no Surefire report has run no tests whatever its status. A Maven run that cannot find a pinned artefact in the seeded local repository ends with status 1 and `... in offline mode and the artifact ... has not been downloaded from it before`: in the unsandboxed baseline that is an infrastructure failure (the image lacks what the exercise pins) and aborts the exercise. Under the layers the line classifies nothing, because a Landlock refusal of a file in the local repository may well surface as the same line: the run is a failed run like any other, so it leads to a grant only through denials attributed to the layer under test (A.6.3), and to an abort when it has none after the unobserved rerun (A.6.4). The `infra_failure` flag is recorded for such a run but never decides it. The `no_source` patterns and the missing-artefact pattern are separate fields and never stand in for each other.
2. **The baseline is repeated** three times unsandboxed; disagreement aborts the exercise as flaky.
3. **The permissive layered run** separates "the layers' fixed rules break this exercise" from "the policy is too narrow".
4. **A grant needs an attributed denial**: in the domain, refused by the layer under test, confirmed by the control replay. A failing run without one is rerun once unobserved; if it still fails, the exercise aborts.
5. **The network cannot be a variable**: `--network none`, pinned dependencies and pre-populated caches; an external connect attempt aborts unless declared.
6. **The observer cannot be the reason**: an observed run that fails without a denial is rerun unobserved before anything is concluded, and every verification run is unobserved.

## A.9 Outputs

Per exercise, written by the prune container into `/var/tmp/path_sets` (the existing shared mount):

- `<lang>_<exercise>.cfg`: a complete Phobos configuration (filesystem sections, `[connect]`, `[bind]`, `[limits]`) in the format `phobos-policysystem.sh` reads, LF, sorted, comment header naming the pruner version, kernel, Landlock ABI, uid and date.
- `<lang>_<exercise>.json`: the record (schema version 2): every run with its shape, verdict and duration; every denial with its attribution and the grant it produced or the reason it produced none; harmless denials; fixed-rule refusals; measurements; minimisation log; SHA-256 of the `.cfg`.

The orchestrator then writes into `var/tmp/opt/core/config`:

- `BaseLanguage-<lang>.cfg`: the union of the filesystem sections of every exercise of the language, hierarchy-normalised, plus the union of the network rules. No `[limits]` (A.6.5).
- `exercises/<lang>_<exercise>.cfg`: each exercise's configuration minus what the base already grants (an entry whose rights are covered by the base's union along its ancestors is dropped), plus its `[limits]`.
- `TailPhobos.cfg` as today.
- The debug comparisons as today, computed from the `.cfg` sections.

The union base keeps today's deployment model (one base, optional `--config`), so adopting it needs no Artemis change; Q2 asks whether Markus wants an intersection base with mandatory per-exercise configurations instead. A final step re-verifies each exercise in the prune image under the merged base plus its `exercises/` remainder, because that pair, not the per-exercise policy it was pruned with, is what grading will apply.

## A.10 Tests, both directions

- **Unit (pytest, `tests/python/`)**: the strace parser (quoted and escaped paths, `<unfinished ...>`/`<... resumed>` pairs, decorated descriptors, signals and exit lines), the in-domain process tree, the call-to-right table of A.6.2, the control replay classification (against a fixture tree with a mode-000 file), generalisation, compaction and hierarchy normalisation (directions pinned as in A.7), ddmin on a synthetic oracle, the cfg renderer (accepted by the real parser in a shell test), the network rule derivation, the margins and the limit signatures, the verdict comparison (JUnit, `NO-SOURCE`, infra patterns).
- **Integration (shell, in the prune image, ordinary container, `--network none`)**: a fixture exercise under `tests/integration/layer-prune-fixture/` whose build script reads a needed file, tries an optional file and does without it, writes build output, creates temporary files with random names, starts a loopback server and connects to it, attempts an external connection and does without it, and writes JUnit XML whose tests pass only when the needed accesses worked. The suite asserts the **permitted** direction (the derived configuration passes under `phobos.sh` with every layer on) and the **forbidden** direction (`/srv/prune-fixture/unneeded/secret.txt`, the optional file, the prefix sibling `/srv/prune-fixture-secret`, and `10.0.0.1:80` are all refused under the derived configuration, checked with the protection matrix's `probe.c`; the derived limits are below the defaults, and a probe exceeding each is refused or ended). Wrong-reason variants: `FIXTURE_FLAKY=1` aborts as flaky and writes no `.cfg`; `FIXTURE_NO_SOURCE=1` is a failed verdict; `FIXTURE_SETSID=1` aborts as "incompatible with a fixed rule"; `FIXTURE_NEEDS_NET=1` aborts as "needs external network".
- **Protection-matrix style**: every grant class gets a deny-and-allow pair in `tests/integration/layer_prune.sh` using `probe.c`'s `OP <name> ret=<n> errno=<NAME>` lines: a granted right works, the next right up on the same path is still refused.
- **Runner capability**: `tests/runner-capability-probe.sh --assert-ptrace` (0 observed, 1 not, 3 cannot tell), reported by `runner-capabilities.yml` beside Landlock and Bubblewrap.

## A.11 CI

- `test.yml`, job `python`: picks up the new `tests/python/test_layer_prune_*.py` with no change.
- `build.yml`, job `run-phase`: after the acceptance suites, build `docker/prune_phase/layers/Dockerfile` on top of the image just built (both architectures, native runners) and run `tests/integration/layer_prune_observer.sh` and, from PR 5 on, `tests/integration/layer_prune.sh` in an ordinary container with `--network none --memory 3g --pids-limit 1024`.
- `lint.yml`: no new tool. `hadolint` reaches the new Dockerfile by its `Dockerfile*` glob, `bandit` and `ruff` reach `var/tmp/helpers/layer_prune/` through the existing `var/tmp/helpers` argument, `shellcheck` reaches the new shell suites.
- `runner-capabilities.yml`: a ptrace row from PR 2; the Bubblewrap row is removed in PR 9.
- `test.yml`: `prune_sandbox.sh`, `prune_producer.sh` and the Bubblewrap install step are removed in PR 9.

## A.12 Documentation

- `README.md`, "Running the pruning phase": rewritten for the new image, the observer, the stages and the outputs; the paragraph "Pruning and grading do not deny in the same way" is replaced by what remains true (a code path the reference never took).
- `CLAUDE.md`: the "Resource discovery, offline" paragraph, the paragraph on the two phases denying differently, the Tech Stack line saying the discovery phase uses Bubblewrap, the bandit note, the project structure (`var/tmp/helpers/layer_prune/`, `docker/prune_phase/layers/`).
- `AGENTS.md`, "A prune run that fails for the wrong reason ...": add "a grant needs an attributed denial" and "the prune container runs without privileges and with `--network none`".
- `var/tmp/pruning/orchestrate_core_idea.txt`: the new artefacts.
- `docker/prune_phase/orchestrate/orchestrate.py` module docstring.
- `SECURITY.md`: one paragraph saying that `strace` is in the prune image only and never in the grading image.
- PR 122 (`feature/docusaurus-documentation`, `documentation/docs/contributor/pruning.md`) describes the Bubblewrap pruner; it has to be rebased onto the documentation changes of PR 8, or PR 8's README text moved into that page if PR 122 merges first.

## A.13 Risks

| Risk | Consequence | Mitigation |
| --- | --- | --- |
| A host with `ptrace_scope=3` or a seccomp profile that blocks `ptrace` | no observer | `--assert-ptrace` probe; the pruner refuses to start rather than fall back to stderr parsing |
| Tracing slows the build | longer prune; timing-sensitive tests fail only under the observer | observed runs only in grow and diagnosis; verdicts and verification unobserved; a failure under the observer without a denial is rerun unobserved; `--seccomp-bpf` when the installed strace supports it unprivileged (measured in PR 3) |
| strace output format differs between versions | parser misreads | golden fixtures captured from the image's own strace in PR 3; version recorded in every `.json` |
| The reference exercise does not exercise what a student solution needs | grading denies a correct solution | directory granularity and compaction (A.7); review of the record; the README says the policy is only as good as the reference |
| Gradle needs `setsid` for its daemon (observed locally with Gradle 9: "could not setsid()") | every run fails under the layers | B2 reports it as "incompatible with a fixed rule" before any grant; Q8 |
| The JVM's address-space reservation depends on the host's memory | `mem_mb` derived on a large prune host differs from grading | record host memory; Q4 |
| The prune kernel's Landlock ABI differs from the grading kernel's | a right the prune kernel does not handle (`RESOLVE_UNIX`, UDP) is never observed | record the ABI; verify on the grading ABI; Q6 |
| A second session or a stale artefact | wrong merge | unchanged: per-language stale removal, `.cfg`/`.json` hash cross-check in the orchestrator |
| Two observers or tracers at once | `EPERM` on attach | one strace per run, the prune container runs nothing else |
| Local apt failures in containers on this Mac | the prune image does not build locally | CI builds it; locally, build on a host where apt works |

## A.14 Open questions for Markus

1. **Observer implementation.** `strace` from the archive (chosen: both architectures, every call decoded, no new C) or a dedicated C tracer in the repository (structured output, no text parsing, more C to lint and maintain)?
2. **Base composition.** Keep a union base plus optional exercise remainders (chosen: no deployment change), or an intersection base with mandatory per-exercise configurations (tighter, needs Artemis to pass `--config`)?
3. **Limit margins.** How much slower than the reference may a correct solution be? Defaults are 3x wall clock and CPU, 1.5x memory.
4. **Memory.** Should exercises pin `-Xmx` so `mem_mb` is host-independent, or should `mem_mb` not be derived and stay at the default 8192?
5. **Python.** There is no Python run-phase image; build one, keep Python on the Bubblewrap pruner until then (PR 9 waits), or retire `BaseLanguage-python.cfg`?
6. **Kernel ABI.** Prune on the grading kernel's ABI only? Would a KVM guest with a 7.2 kernel (PR 161) be welcome, which would also make Landlock audit readable as a second, kernel-native observer?
7. **Generalisation defaults.** The fine-grained roots (`/etc`, `/dev`, `/proc`, `/sys`, `/root`, `/home`, `/run`) and the compaction threshold `k=3`.
8. **Gradle daemon.** If the reference needs `setsid`, should exercises run with `--no-daemon`, pin Gradle 8, or is a change to the group lock wanted (a sandbox change of its own)?
9. **Guard log.** The guard's verbose refusal names only the port. Should it name the address too, for operators? The pruner does not need it.
10. **Budgets.** Is a minimisation budget of 150 runs per exercise acceptable, and what total prune time is tolerable?
11. **External egress.** Should declared hosts in `prune.json` ever be derived and verified by the pruner, or should every external rule stay hand-written?

## A.15 Review record

This design and plan went through a multi-turn review with an independent reviewer before this pull request was opened; the outcome is recorded in Part C.

---

# Part B: Pull requests and tasks

Each pull request is based on `main` after the previous one merged (or stacked on it, in which case the workflows are started with `workflow_dispatch` on its branch and linked, AGENTS.md). Every pull request body follows `.github/PULL_REQUEST_TEMPLATE.md` and is checked with `PR_BODY="$(cat body.md)" java .github/scripts/CheckPullRequestTemplate.java`. Every pull request ends with the full lint set from CLAUDE.md.

| PR | Branch | Content | Grading behaviour changed |
| --- | --- | --- | --- |
| 1 | `feature/prune-on-the-layers-plan` | this plan | no |
| 2 | `ci/probe-ptrace-on-runners` | runner probe: can a Landlock denial be observed by ptrace | no |
| 3 | `feature/prune-observer` | prune image, `BasePrune.cfg`, strace observer, parser, attribution, control replay | no |
| 4 | `feature/prune-verdict-and-runner` | verdict, runner, baseline, permissive run | no |
| 5 | `feature/prune-filesystem-stage` | grow loop, generalisation, cfg renderer, minimisation, fixture suite | no |
| 6 | `feature/prune-network-stage` | network derivation | no |
| 7 | `feature/prune-limits-stage` | sampler, margins, limit signatures, joint verification, containment checks | no |
| 8 | `feature/prune-producer-switch` | per-language entry, artefacts, orchestrator merge, compose, docs, the Maven reference prune (Task 8.4) | no (generated files only) |
| 9 | `feature/retire-bubblewrap-pruner` | remove the Bubblewrap pruner and its tests and probe | no |

Adopting a regenerated `BaseLanguage-java.cfg` into `core/config/` is not part of this plan; it is a later pull request of its own that lists every widening. The same holds for the Maven base of Task 8.4, which the Ares 2 import plan adopts.

**Ordering against the Ares 2 import plan (pull request 163).** Stated there in A.11, and mirrored here: its pull request 5, the Maven reference exercise, is based on `main`, depends on nothing in either plan, and must land before Task 8.4 of this plan's PR 8 runs; its pull request 6, the Maven base, waits for this plan's PR 8 (whose Task 8.4 produced the base) and for its own pull request 4. The Maven lines of the verdict arrive in this plan's PR 4 (Task 4.1) and need nothing from the other plan. Nothing else in either plan waits for the other, and PRs 2 to 7 of this plan can land before the exercise exists.

## PR 2: Ask each runner whether ptrace can observe a Landlock denial

### Task 2.1: The ptrace probe

**Files:**
- Create: `tests/ptrace-observer-capability-probe.c`
- Modify: `tests/runner-capability-probe.sh` (new mode `--assert-ptrace`, new lines in `--report`)
- Modify: `.github/workflows/runner-capabilities.yml` (new step and table row)

**Interfaces:**
- Produces: `runner-capability-probe.sh --assert-ptrace` exiting `0` (a traced child's Landlock `EACCES` was observed at syscall exit), `1` (ptrace refused or the denial was not seen), `3` (Landlock unavailable, compiler missing, or container could not start).

- [ ] **Step 1: Write the probe.** The probe forks a child that calls `PTRACE_TRACEME`, stops itself, applies a Landlock ruleset handling `read_file` and `read_dir` with no rule, and opens `/etc/hostname`. The parent follows with `PTRACE_SYSCALL` and `PTRACE_GET_SYSCALL_INFO`, and prints exactly one of `OBSERVED openat errno=EACCES`, `TRACEME-REFUSED errno=<NAME>`, `NOT-OBSERVED`, `NO-LANDLOCK`. Base it on the spike in A.3.5, with one declaration per line, every return value checked, and `strerrorname_np` for the errno name.

```c
/* The parent's decision, once the child has ended. */
static int verdict(bool observed, bool landlock_available) {
    if (!landlock_available) {
        puts("NO-LANDLOCK");
        return EXIT_INDETERMINATE;
    }
    if (observed) {
        puts("OBSERVED openat errno=EACCES");
        return EXIT_AVAILABLE;
    }
    puts("NOT-OBSERVED");
    return EXIT_UNAVAILABLE;
}
```

- [ ] **Step 2: Add the mode to the probe script.** Mirror `--assert-landlock`: compile the probe inside `PROBE_CONTAINER_IMAGE` (default `ubuntu:26.04`) started with `docker run --rm --network none` and nothing else, map `OBSERVED` to 0, `TRACEME-REFUSED`/`NOT-OBSERVED` to 1, everything else to 3. `--report` adds `/proc/sys/kernel/yama/ptrace_scope` (or "absent") and the probe's line.
- [ ] **Step 3: Run it locally** in Docker Desktop: `bash tests/runner-capability-probe.sh --assert-ptrace; echo "status $?"`. Expected: `status 0`.
- [ ] **Step 4: Add the workflow step and the table row** "ptrace observes a Landlock denial, plain container" in `runner-capabilities.yml`, using `.github/scripts/record-capability.sh ptrace --assert-ptrace` the way the Landlock row does.
- [ ] **Step 5: Lint**: `shellcheck -x -S warning tests/runner-capability-probe.sh`, the gcc-14 `-fanalyzer` gate and `cppcheck --std=c23` on the new C file, `actionlint`, `yamllint --strict .`, `ec --no-color`.
- [ ] **Step 6: Commit** `git add tests/ptrace-observer-capability-probe.c tests/runner-capability-probe.sh .github/workflows/runner-capabilities.yml && git commit -m "Ask each runner whether a traced process's Landlock denial can be observed without privileges"`, then start `runner-capabilities.yml` with `workflow_dispatch` and record the verdict of each runner in the pull request.

## PR 3: The prune image and the observer

### Task 3.1: The prune image and an empty base

**Files:**
- Create: `docker/prune_phase/layers/Dockerfile`
- Create: `docker/prune_phase/layers/BasePrune.cfg`
- Create: `tests/integration/layer_prune_observer.sh`
- Modify: `.github/workflows/build.yml` (build the prune image after the run-phase acceptance suites; run the new suite)

**Interfaces:**
- Produces: image `phobos-prune-layers:<tag>` with `PHOBOS_HOME=/var/tmp/opt/core`, the shipped scripts and binaries unchanged, `BaseLanguage-java.cfg` removed from `PHOBOS_HOME`, `BasePrune.cfg` in its place, `strace` and `python3` installed.

- [ ] **Step 1: Write the failing suite.** `tests/integration/layer_prune_observer.sh` sources `tests/harness.sh` and checks, in the prune image:

```bash
# The base the prune image ships must grant nothing beyond what a run cannot start without, and
# phobos-policysystem.sh must accept it.
check_empty_base_is_accepted() {
  local spec
  spec="$(mktemp -d /var/tmp/phobos-spec-check.XXXXXX)"
  if "${PHOBOS_HOME}/phobos-policysystem.sh" --spec-dir "$spec" --tail-flags-file "${PHOBOS_HOME}/TailPhobos.cfg" >/dev/null 2>&1; then
    ok "the prune base is accepted by the policy parser"
  else
    bad "the prune base is accepted by the policy parser"
  fi
  rm -rf "$spec"
}

# Under the prune base a read of /etc/hostname is refused, and strace records that refusal with
# its path and errno.
check_strace_sees_a_landlock_refusal() {
  local trace
  trace="$(mktemp)"
  strace -f -qq -o "$trace" -e trace=openat,execve,landlock_restrict_self \
    "${PHOBOS_HOME}/phobos.sh" --config "$FIXTURE_CFG" -- /bin/cat /etc/hostname >/dev/null 2>&1
  if grep -q 'openat(.*"/etc/hostname".*= -1 EACCES' "$trace"; then
    ok "strace records the Landlock refusal of /etc/hostname"
  else
    bad "strace records the Landlock refusal of /etc/hostname" "$(tail -5 "$trace")"
  fi
  rm -f "$trace"
}
```

`FIXTURE_CFG` grants `[read]`/`[execute]` on `/usr`, `/lib`, `/bin` and `/lib64` where they exist, so `cat` can start and only `/etc/hostname` is refused; the permitted neighbour `cat /usr/share/common-licenses/GPL-3` (or any file that exists under `/usr` in the image) must succeed in the same suite.

- [ ] **Step 2: Run it against the run-phase image to see it fail** (no strace there, and the base is the Java one): `docker run --rm --network none -v "$PWD/tests:/tests:ro" phobos-run-phase:ci bash /tests/integration/layer_prune_observer.sh`. Expected: failures naming strace and the base.
- [ ] **Step 3: Write `BasePrune.cfg`** as a comment-only file. If Step 1's first check shows the parser refuses a base with no section, the file instead holds `[read]` and `[write]` naming `/dev/null` only, and the comment says why.

```
# The prune image's base grants nothing. The pruner passes everything a run may reach as an
# exercise configuration, so every grant in a pruned policy is one the pruner had a denial for.
```

- [ ] **Step 4: Write the Dockerfile.**

```dockerfile
# The prune image is the run-phase image plus the observer, so a prune run goes through exactly
# the layers a grading run does. The base the run-phase image ships is replaced by one that grants
# nothing: the pruner builds every policy itself, from denials.
ARG RUN_PHASE_IMAGE=phobos-run-phase:ci
FROM ${RUN_PHASE_IMAGE}

# strace is the observer (ptrace, no privileges); python3 runs the pruner.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    strace \
 && rm -rf /var/lib/apt/lists/*

RUN rm -f "${PHOBOS_HOME}"/Base*.cfg
COPY BasePrune.cfg ${PHOBOS_HOME}/BasePrune.cfg
```

The image gets its `ENTRYPOINT` in Task 8.1, once `main.py` exists; until then every suite starts it with `--entrypoint bash`.

Pin `strace` to the archive version the CI build resolves (`strace=<version>`) once the first CI build has printed it, as hadolint's `DL3008` asks; until then the `.hadolint.yaml` exception that the run-phase Dockerfile uses applies, with a comment.

- [ ] **Step 5: Build and run the suite**: `docker build --build-arg RUN_PHASE_IMAGE=phobos-run-phase:ci -t phobos-prune-layers:local docker/prune_phase/layers && docker run --rm --network none --entrypoint bash -v "$PWD/tests:/tests:ro" phobos-prune-layers:local /tests/integration/layer_prune_observer.sh`. Expected: `N passed, 0 failed`.
- [ ] **Step 6: Wire it into `build.yml`** after the acceptance steps of the `run-phase` job (same runner matrix), with the same `docker run` line.
- [ ] **Step 7: Lint** (`hadolint`, `shellcheck`, `actionlint`, `yamllint`, `ec`) and **commit** the four files explicitly by name.

### Task 3.2: The record format and the strace parser

**Files:**
- Create: `var/tmp/helpers/layer_prune/__init__.py` (empty docstring module)
- Create: `var/tmp/helpers/layer_prune/record.py`
- Create: `var/tmp/helpers/layer_prune/strace_parse.py`
- Create: `tests/python/test_layer_prune_strace_parse.py`
- Create: `tests/python/fixtures/strace/` (golden lines captured from the prune image)

**Interfaces:**
- Produces:
  - `record.Syscall(pid: int, name: str, arguments: str, result: int, errno: str | None)`, frozen dataclass.
  - `strace_parse.parse_line(line: str) -> Syscall | None` (a complete line or a resumed one already joined).
  - `strace_parse.parse_trace(lines: Iterable[str]) -> Trace`, where `Trace` has `syscalls: list[Syscall]` (failed calls, `landlock_restrict_self`, `clone*`, `fork`, `vfork`, `socket`, `bind`, `listen`, `getsockname` successes) and `domain_pids: frozenset[int]`.
  - `strace_parse.STRACE_ARGUMENTS: tuple[str, ...]`, the option list every observed run uses.

- [ ] **Step 1: Capture golden lines.** In the prune image run `strace -f -qq -y -s 4096 -o /tmp/g.txt -e trace=%file,%network,%process,landlock_restrict_self,setsid,setpgid,ioctl phobos.sh --config <Task 3.1 cfg> -- bash -c 'cat /etc/hostname; mkdir /etc/x; exec 3<>/dev/tcp/10.0.0.1/80'` and keep 30 representative lines (a refused `openat`, a refused `mkdir`, a refused `connect`, an `<unfinished ...>`/`<... resumed>` pair, a `clone` returning a pid, `landlock_restrict_self(...) = 0`, an `execve`, a `+++ exited with 0 +++` line, a `--- SIGCHLD ---` line, an escaped path with `\"` and `\n`) in `tests/python/fixtures/strace/basic.txt`. Record the strace version in `tests/python/fixtures/strace/VERSION`. Check whether `AT_FDCWD` is decorated with `<path>`; write the answer in `VERSION` too.
- [ ] **Step 2: Write the failing tests.**

```python
"""Checks how a strace -f log becomes the system calls the pruner reasons about."""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import strace_parse  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "python" / "fixtures" / "strace"


def test_a_refused_openat_keeps_its_path_and_errno():
    line = '210 openat(AT_FDCWD</var/tmp/testing-dir>, "/var/log/dpkg.log", O_RDONLY) = -1 EACCES (Permission denied)'
    call = strace_parse.parse_line(line)
    assert call.pid == 210
    assert call.name == "openat"
    assert call.result == -1
    assert call.errno == "EACCES"
    assert '"/var/log/dpkg.log"' in call.arguments


def test_an_unfinished_call_is_joined_with_its_resumption():
    lines = [
        '7 openat(AT_FDCWD</w>, "a", O_RDONLY <unfinished ...>',
        "8 +++ exited with 0 +++",
        "7 <... openat resumed>) = -1 EACCES (Permission denied)",
    ]
    trace = strace_parse.parse_trace(lines)
    refused = [call for call in trace.syscalls if call.name == "openat"]
    assert len(refused) == 1
    assert refused[0].errno == "EACCES"


def test_only_processes_after_landlock_restrict_self_are_in_the_domain():
    lines = [
        "100 clone(child_stack=NULL, flags=SIGCHLD) = 101",
        "101 landlock_restrict_self(3, 0) = 0",
        "101 clone(child_stack=NULL, flags=SIGCHLD) = 102",
        "100 clone(child_stack=NULL, flags=SIGCHLD) = 103",
    ]
    trace = strace_parse.parse_trace(lines)
    assert trace.domain_pids == frozenset({101, 102})


def test_an_escaped_path_is_unescaped():
    line = r'5 openat(AT_FDCWD</w>, "/tmp/a\"b\nc", O_RDONLY) = -1 EACCES (Permission denied)'
    call = strace_parse.parse_line(line)
    assert strace_parse.path_argument(call, 1) == '/tmp/a"b\nc'


def test_every_golden_line_parses_or_is_a_known_non_call():
    for raw in (FIXTURES / "basic.txt").read_text().splitlines():
        call = strace_parse.parse_line(raw)
        assert call is not None or strace_parse.is_non_call(raw), raw
```

- [ ] **Step 3: Run them to see them fail**: `python3 -m pytest tests/python/test_layer_prune_strace_parse.py -q`. Expected: `ModuleNotFoundError: No module named 'layer_prune'`.
- [ ] **Step 4: Implement `record.py` and `strace_parse.py`.** The line grammar: `^(?P<pid>\d+) +(?P<name>[a-z0-9_]+)\((?P<arguments>.*)\) += (?P<result>-?\d+|\?|0x[0-9a-f]+)(?: (?P<errno>E[A-Z0-9]+) \(.*\))?$`; `<unfinished ...>` lines are buffered per pid and completed by the next `<... name resumed>` of that pid; `+++`, `---` and `strace:` lines are non-calls. `path_argument(call, index)` splits the arguments on top-level commas (outside quotes, braces, brackets and angle brackets) and unescapes C escapes (`\"`, `\\`, `\n`, `\t`, `\xHH`, octal). `domain_pids` is computed from `landlock_restrict_self = 0` and the pids returned by `clone`, `clone3`, `fork` and `vfork` of in-domain processes, in log order. Every module and function has a docstring saying what it does and assumes.

```python
"""Turns a strace -f log into the system calls the pruner reasons about."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable

from layer_prune.record import Syscall

# The options every observed run passes to strace: follow every process, quiet attach and exit
# notices, decorate every descriptor with the path it names, keep whole strings, and trace only
# the calls a layer can refuse plus the ones that build the process tree.
STRACE_ARGUMENTS = (
    "-f",
    "-qq",
    "-y",
    "-s", "4096",
    "-e", "trace=%file,%network,%process,%desc,landlock_restrict_self,setsid,setpgid,ioctl",
)

LINE = re.compile(
    r"^(?P<pid>\d+) +(?P<name>[a-z0-9_]+)\((?P<arguments>.*)\) += "
    r"(?P<result>-?\d+|\?|0x[0-9a-f]+)(?: (?P<errno>E[A-Z0-9]+) \(.*\))?"
)
UNFINISHED = re.compile(r"^(?P<pid>\d+) +(?P<head>.*) <unfinished \.\.\.>$")
RESUMED = re.compile(r"^(?P<pid>\d+) +<\.\.\. (?P<name>[a-z0-9_]+) resumed>(?P<tail>.*)$")
NON_CALL = re.compile(r"^(\d+ +)?(\+\+\+ |--- |strace: )")
FORKING_CALLS = frozenset({"clone", "clone3", "fork", "vfork"})


@dataclasses.dataclass(frozen=True)
class Trace:
    """The calls of one observed run that matter to the pruner, and the pids inside the domain."""

    syscalls: list[Syscall]
    domain_pids: frozenset[int]
```

(`%desc` is included so `getsockname`, `ftruncate` and `ioctl` arrive; the trace keeps only refused calls plus the successes named in the Interfaces.)

- [ ] **Step 5: Run the tests until they pass**, then `ruff check --no-cache .` and `bandit --recursive --ini .bandit --severity-level medium docker/prune_phase/orchestrate var/tmp/helpers`.
- [ ] **Step 6: Commit** the five paths explicitly.

### Task 3.3: Attribution and the control replay

**Files:**
- Create: `var/tmp/helpers/layer_prune/attribute.py`
- Create: `var/tmp/helpers/layer_prune/control.py`
- Create: `tests/python/test_layer_prune_attribute.py`
- Create: `tests/python/test_layer_prune_control.py`

**Interfaces:**
- Consumes: `Syscall`, `Trace`, `strace_parse.path_argument`.
- Produces:
  - `record.Denial(pid: int, layer: str, operation: str, objects: tuple[str, ...], sections: frozenset[str], address: str | None, port: int | None, transport: str | None, errno: str)` with `layer` one of `"filesystem"`, `"network"`, `"fixed"`, `"limit"`, `"other"`.
  - `attribute.denials(trace: Trace, working_directory: str) -> list[Denial]`.
  - `attribute.SECTION_*` constants: `SECTION_READ = "read"`, `SECTION_EXECUTE = "execute"`, `SECTION_WRITE = "write"`, `SECTION_CREATE = "create"`, `SECTION_CREATE_IPC = "create-ipc"`, `SECTION_CREATE_SYMLINK = "create-symlink"`, `SECTION_DELETE = "delete"`, `SECTION_RESTRUCTURE = "restructure"`.
  - `control.landlock_caused(denial: Denial) -> bool`.

- [ ] **Step 1: Write the failing tests**, one per row of the table in A.6.2, for example:

```python
def test_a_refused_read_of_a_file_asks_for_read_on_that_file():
    trace = trace_of('300 landlock_restrict_self(3, 0) = 0',
                     '300 openat(AT_FDCWD</w>, "/srv/a/data.txt", O_RDONLY) = -1 EACCES (Permission denied)')
    [denial] = attribute.denials(trace, "/w")
    assert denial.layer == "filesystem"
    assert denial.objects == ("/srv/a/data.txt",)
    assert denial.sections == frozenset({attribute.SECTION_READ})


def test_a_refused_create_asks_for_create_on_the_parent():
    trace = trace_of('300 landlock_restrict_self(3, 0) = 0',
                     '300 openat(AT_FDCWD</w>, "build/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EACCES (Permission denied)')
    [denial] = attribute.denials(trace, "/w")
    assert denial.objects == ("/w/build",)
    assert denial.sections == frozenset({attribute.SECTION_CREATE})


def test_a_refused_setsid_is_a_fixed_rule_and_never_a_grant():
    trace = trace_of('300 landlock_restrict_self(3, 0) = 0', '300 setsid() = -1 EPERM (Operation not permitted)')
    [denial] = attribute.denials(trace, "/w")
    assert denial.layer == "fixed"
    assert denial.sections == frozenset()


def test_a_refused_connect_keeps_address_port_and_transport():
    trace = trace_of('300 landlock_restrict_self(3, 0) = 0',
                     '300 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 4<TCP:[1]>',
                     '300 connect(4<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.1")}, 16) = -1 EACCES (Permission denied)')
    [denial] = attribute.denials(trace, "/w")
    assert denial.layer == "network"
    assert (denial.address, denial.port, denial.transport) == ("10.0.0.1", 80, "tcp")


def test_a_refusal_outside_the_domain_is_ignored():
    trace = trace_of('200 openat(AT_FDCWD</w>, "/srv/a", O_RDONLY) = -1 EACCES (Permission denied)')
    assert attribute.denials(trace, "/w") == []


def test_enoent_is_not_a_denial():
    trace = trace_of('300 landlock_restrict_self(3, 0) = 0',
                     '300 openat(AT_FDCWD</w>, "/srv/missing", O_RDONLY) = -1 ENOENT (No such file or directory)')
    assert attribute.denials(trace, "/w") == []
```

and for the control replay, against a tree made in `tmp_path`:

```python
def test_a_file_the_uid_cannot_read_is_not_landlock_caused(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("x")
    secret.chmod(0)
    denial = read_denial(str(secret))
    if os.geteuid() == 0:
        pytest.skip("root reads a mode-000 file, so DAC cannot refuse here")
    assert control.landlock_caused(denial) is False


def test_a_readable_file_refused_in_the_sandbox_is_landlock_caused(tmp_path):
    readable = tmp_path / "readable"
    readable.write_text("x")
    assert control.landlock_caused(read_denial(str(readable))) is True
```

- [ ] **Step 2: Run them to see them fail.**
- [ ] **Step 3: Implement.** Relative paths are joined with the decorated directory descriptor (`AT_FDCWD</w>` or `3</srv>`); when strace did not decorate `AT_FDCWD` (recorded in `VERSION`), with the per-process working directory, which starts at `working_directory`, is inherited at every `clone`/`fork`/`vfork` and follows every successful `chdir`/`fchdir`. Only `EACCES`, `EPERM` and `EXDEV` (plus `EMFILE`, `EAGAIN`, `ENOMEM` as `layer="limit"`) produce a `Denial`. `objects` for creation and removal is the parent directory; for `rename*` both parents. `control.landlock_caused` replays as A.6.3 lists and never follows a symbolic link (`O_NOFOLLOW`).
- [ ] **Step 4: Run the tests until they pass; lint.**
- [ ] **Step 5: Extend `tests/integration/layer_prune_observer.sh`** with an end-to-end check: run `python3 -c` over a real strace log of the Task 3.1 command and assert exactly one filesystem denial for `/etc/hostname` with `read`, and that `/usr` reads produced none (both directions).
- [ ] **Step 6: Commit** the five paths explicitly.

## PR 4: Verdict, runner, baseline

### Task 4.1: The verdict

**Files:**
- Create: `var/tmp/helpers/layer_prune/verdict.py`
- Create: `tests/python/test_layer_prune_verdict.py`

**Interfaces:**
- Produces:
  - `verdict.Verdict(exit_class: str, tests: tuple[tuple[str, str], ...], tests_ran: bool, no_source: bool, infra_failure: bool)`, `exit_class` one of `"success"`, `"tests-failed"`, `"failure"`, `"timeout"`, `"signalled"`.
  - `verdict.read_verdict(status: int, log_text: str, report_paths: list[pathlib.Path]) -> Verdict`.
  - `verdict.same_outcome(first: Verdict, second: Verdict) -> bool`.
  - `verdict.DEFAULT_REPORT_GLOBS = ("build/test-results/**/*.xml", "target/surefire-reports/*.xml")`.
  - `verdict.NO_SOURCE_PATTERNS = ("NO-SOURCE", "No tests to run", "Tests are skipped.")`, Gradle's line and Maven's two (A.8), the second matching both `No tests to run.` and `No tests to run!`.
  - `verdict.MAVEN_OFFLINE_MISSING_PATTERN = "in offline mode and the artifact"`, one of the infrastructure patterns, which only the baseline treats as an abort (A.8).

- [ ] **Step 1: Write the failing tests.**

```python
def test_two_runs_agree_only_when_the_same_tests_had_the_same_outcomes(tmp_path):
    first = verdict.read_verdict(0, "", [junit(tmp_path / "a.xml", {"T.a": "passed", "T.b": "passed"})])
    second = verdict.read_verdict(0, "", [junit(tmp_path / "b.xml", {"T.a": "passed", "T.b": "failed"})])
    assert not verdict.same_outcome(first, second)


def test_no_source_with_status_zero_is_not_a_success():
    result = verdict.read_verdict(0, "> Task :compileJava NO-SOURCE\n", [])
    assert result.no_source
    assert not result.tests_ran


def test_an_infrastructure_failure_is_recognised():
    result = verdict.read_verdict(0, "Traceback (most recent call last):\n", [])
    assert result.infra_failure


def test_a_run_with_no_reports_did_not_run_tests():
    assert verdict.read_verdict(0, "BUILD SUCCESSFUL\n", []).tests_ran is False


def test_status_fourteen_is_a_timeout():
    assert verdict.read_verdict(14, "", []).exit_class == "timeout"


def test_maven_without_tests_and_status_zero_is_not_a_success():
    result = verdict.read_verdict(0, "[INFO] No tests to run.\n[INFO] BUILD SUCCESS\n", [])
    assert result.no_source
    assert not result.tests_ran


def test_maven_with_skipped_tests_and_status_zero_is_not_a_success():
    result = verdict.read_verdict(0, "[INFO] Tests are skipped.\n[INFO] BUILD SUCCESS\n", [])
    assert result.no_source
    assert not result.tests_ran


def test_a_surefire_report_counts_like_any_junit_report(tmp_path):
    report = junit(tmp_path / "TEST-de.phobos.reference.AdderTest.xml", {"de.phobos.reference.AdderTest.addsTwoNumbers": "passed"})
    result = verdict.read_verdict(0, "[INFO] BUILD SUCCESS\n", [report])
    assert result.tests_ran
    assert not result.no_source


def test_a_missing_artefact_in_offline_mode_is_an_infrastructure_failure():
    log_text = "[ERROR] Cannot access central (https://repo.maven.apache.org/maven2) in offline mode and the artifact org.junit.jupiter:junit-jupiter-engine:jar:5.13.4 has not been downloaded from it before.\n"
    assert verdict.read_verdict(1, log_text, []).infra_failure
```

The Maven log lines are the ones measured in A.8, copied verbatim.

- [ ] **Step 2: Run to see them fail. Step 3: Implement** with `xml.etree.ElementTree` (a `testcase` with a `failure` or `error` child is `failed`, with `skipped` is `skipped`, otherwise `passed`; the test id is `classname.name`); the patterns are copied from `detect_minimal_fs.sh`'s `IGNORABLE_FAILURE_PATTERNS`, `UNIGNORABLE_SUCCESS_PATTERNS` and `INFRA_FAILURE_PATTERNS`, named once as module constants. Bandit flags `xml.etree`; the reports are written by the exercise's own build inside the prune container, so use `defusedxml` only if it is in the image, otherwise add a `# nosec B314` with the reason on the line above, as AGENTS.md requires for a suppression.
- [ ] **Step 4: Pass, lint, commit** both paths.

### Task 4.2: The runner, the baseline and the permissive run

**Files:**
- Create: `var/tmp/helpers/layer_prune/runner.py`
- Create: `var/tmp/helpers/layer_prune/cfgfile.py` (rendering only; checks follow in Task 5.2)
- Create: `tests/python/test_layer_prune_runner.py`

**Interfaces:**
- Consumes: `Verdict`, `read_verdict`, `STRACE_ARGUMENTS`, `parse_trace`.
- Produces:
  - `runner.RunShape(observe: bool, network: bool, limits: bool, sample: bool)`.
  - `runner.RunResult(verdict: Verdict, status: int, trace: Trace | None, samples: list | None, wall_seconds: float, log_path: pathlib.Path)`.
  - `runner.run_direct(exercise: Exercise) -> RunResult`.
  - `runner.run_layers(exercise: Exercise, policy: Policy, shape: RunShape) -> RunResult`, which first passes the candidate through the acceptance gate (`phobos-policysystem.sh --spec-dir <temporary> --config <candidate>`) and raises `runner.PrunerDefect(status: int, log_path: pathlib.Path)` when the gate refuses or when the run ends with `2`, `11`, `15` or `125` together with Phobos's own stderr marker for that status (A.6.4).
  - `runner.Exercise(name: str, workdir: pathlib.Path, build_script: str, report_globs: tuple[str, ...], declared_hosts: tuple[str, ...])`, read from the exercise directory and its optional `prune.json` (the contract of A.6.8); `runner.read_exercise` raises `runner.ExerciseRefused(reason: str)` when the directory has no executable build script or its committed copy already matches one of its report globs.
  - `cfgfile.Policy(fs: dict[str, frozenset[str]], connect: tuple[str, ...], bind: tuple[str, ...], limits: dict[str, int])`.
  - `cfgfile.render(policy: Policy) -> str`.
  - `cfgfile.permissive_policy(root: pathlib.Path) -> Policy`.

- [ ] **Step 1: Write failing tests** with a fake `phobos.sh` (a script in `tmp_path` that records its argument vector and exits with a chosen status) so the runner's command line is checked without Docker:

```python
def test_an_observed_run_puts_strace_outermost_and_passes_the_candidate_as_config(tmp_path):
    fake = fake_phobos(tmp_path, status=0)
    result = runner.run_layers(exercise(tmp_path), empty_policy(), runner.RunShape(observe=True, network=False, limits=False, sample=False), phobos=fake, strace=fake_strace(tmp_path))
    argv = recorded_argv(tmp_path)
    assert argv[0].endswith("strace")
    assert "--config" in argv
    assert "-nnr" in argv
    assert result.status == 0


def test_limits_off_writes_zero_for_every_limit(tmp_path):
    text = cfgfile.render(cfgfile.Policy(fs={}, connect=(), bind=(), limits=runner.LIMITS_OFF))
    assert "timeout=0" in text
    assert "mem_mb=0" in text


@pytest.mark.parametrize(("status", "marker"), [(11, "(PHB-EPOLICY)"), (15, "(PHB-ERUNTIME)"), (125, "[phobos-landlock-filesystem-and-networksystem] cannot open /x")])
def test_a_run_phobos_itself_stopped_is_a_pruner_defect_not_a_verdict(tmp_path, status, marker):
    fake = fake_phobos(tmp_path, status=status, stderr=marker)
    with pytest.raises(runner.PrunerDefect):
        runner.run_layers(exercise(tmp_path), empty_policy(), runner.RunShape(observe=False, network=True, limits=True, sample=False), phobos=fake)


@pytest.mark.parametrize("status", [2, 11, 15, 125])
def test_the_commands_own_status_without_a_phobos_marker_is_a_verdict(tmp_path, status):
    fake = fake_phobos(tmp_path, status=status, stderr="make: *** [all] Error 2")
    result = runner.run_layers(exercise(tmp_path), empty_policy(), runner.RunShape(observe=False, network=True, limits=True, sample=False), phobos=fake)
    assert result.status == status


def test_an_exercise_that_already_holds_a_report_is_refused(tmp_path):
    exercise_dir = tmp_path / "maven-reference"
    (exercise_dir / "target" / "surefire-reports").mkdir(parents=True)
    (exercise_dir / "target" / "surefire-reports" / "TEST-Stale.xml").write_text("<testsuite/>")
    (exercise_dir / "build_script.sh").write_text("exit 0\n")
    (exercise_dir / "build_script.sh").chmod(0o755)
    (exercise_dir / "prune.json").write_text('{"report_globs": ["target/surefire-reports/TEST-*.xml"], "declared_hosts": []}')
    with pytest.raises(runner.ExerciseRefused, match="report"):
        runner.read_exercise(exercise_dir)


def test_the_permissive_policy_keeps_the_specification_parent_out_of_every_write_path(tmp_path):
    policy = cfgfile.permissive_policy(pathlib.Path("/"))
    assert not any(path in ("/", "/var", "/var/tmp") for path, sections in policy.fs.items() if "write" in sections)
```

- [ ] **Step 2: Run to see them fail. Step 3: Implement.** `run_layers` writes the candidate to a temporary `.cfg` under `/run/layer-prune` (outside every write path), runs `phobos.sh --config <cfg> [-nnr] [-nrr] -- bash <build_script>` with `cwd=/var/tmp/testing-dir`, wrapped in `strace <STRACE_ARGUMENTS> -o <trace>` when `observe`, with a hard outer `timeout` of `budget.run_seconds`, captures stdout and stderr to the log, and builds the verdict from the log and the report globs. `run_direct` runs `bash <build_script>` with the same cwd and environment. Before each run the exercise copy is restored from a pristine copy (`shutil.copytree` into `/var/tmp/testing-dir`), so no run sees another's output. `permissive_policy` grants `[read]` and `[execute]` on `/`, and every write-class section on each top-level directory except `/var`, `/proc`, `/sys` and `/dev`, on each child of `/var` except `/var/tmp`, and on `/var/tmp/testing-dir`; it grants `/dev/null` read and write; `[connect] allow 127.0.0.1:*`, `allow [::1]`, `allow localhost`; `[bind] allow 0`, `allow 0 udp`.
- [ ] **Step 4: Pass, lint, commit.**

## PR 5: The filesystem stage

### Task 5.1: Generalisation, compaction and hierarchy normalisation

**Files:**
- Create: `var/tmp/helpers/layer_prune/generalise.py`
- Create: `tests/python/test_layer_prune_generalise.py`

**Interfaces:**
- Consumes: `Denial`, the `SECTION_*` constants.
- Produces:
  - `generalise.Snapshot(existing: frozenset[str])`, the paths under the exercise and the write grants that existed before the run, plus `Snapshot.existed(path) -> bool` that answers for system paths by `os.path.lexists` at snapshot time.
  - `generalise.grants_for(denials: list[Denial], snapshot: Snapshot, fine_roots: tuple[str, ...]) -> dict[str, frozenset[str]]`.
  - `generalise.compact(grants: dict[str, frozenset[str]], threshold: int, fine_roots: tuple[str, ...]) -> dict[str, frozenset[str]]`.
  - `generalise.normalise_hierarchy(grants: dict[str, frozenset[str]]) -> dict[str, frozenset[str]]`.
  - `generalise.DEFAULT_FINE_ROOTS = ("/etc", "/dev", "/proc", "/sys", "/root", "/home", "/run")`.

- [ ] **Step 1: Write the failing tests, each naming the direction it pins.**

```python
def test_a_read_outside_fine_roots_is_granted_on_the_directory_permissively():
    grants = generalise.grants_for([read("/usr/lib/jvm/lib/modules")], snapshot_with("/usr/lib/jvm/lib"), generalise.DEFAULT_FINE_ROOTS)
    assert grants == {"/usr/lib/jvm/lib": frozenset({"read"})}


def test_a_read_under_etc_is_granted_on_the_file_only():
    grants = generalise.grants_for([read("/etc/hosts")], snapshot_with("/etc"), generalise.DEFAULT_FINE_ROOTS)
    assert grants == {"/etc/hosts": frozenset({"read"})}


def test_a_file_the_run_created_is_granted_on_the_nearest_pre_existing_ancestor():
    grants = generalise.grants_for([create("/w/build/tmp/x123")], snapshot_with("/w", "/w/build"), generalise.DEFAULT_FINE_ROOTS)
    assert grants == {"/w/build": frozenset({"create"})}


def test_compaction_never_reaches_the_root_or_a_top_level_write():
    grants = {"/usr/a": frozenset({"write"}), "/usr/b": frozenset({"write"}), "/usr/c": frozenset({"write"})}
    assert generalise.compact(grants, 3, generalise.DEFAULT_FINE_ROOTS) == grants


def test_three_siblings_with_equal_read_rights_compact_into_their_parent():
    grants = {"/usr/lib/a": frozenset({"read"}), "/usr/lib/b": frozenset({"read"}), "/usr/lib/c": frozenset({"read"})}
    assert generalise.compact(grants, 3, generalise.DEFAULT_FINE_ROOTS) == {"/usr/lib": frozenset({"read"})}


def test_a_strict_subset_under_a_wider_ancestor_is_raised_not_dropped():
    grants = {"/usr": frozenset({"read", "execute"}), "/usr/bin": frozenset({"read"})}
    assert generalise.normalise_hierarchy(grants) == {"/usr": frozenset({"read", "execute"}), "/usr/bin": frozenset({"read", "execute"})}


def test_a_path_with_a_wildcard_character_is_generalised_to_its_parent():
    grants = generalise.grants_for([read("/srv/a[1]/f")], snapshot_with("/srv"), ("/srv",))
    assert all("[" not in path for path in grants)
```

- [ ] **Step 2: Fail. Step 3: Implement** (pure functions, `os.path.realpath` applied by the caller before `grants_for` so the tests stay hermetic; the caller is Task 5.3). **Step 4: Pass, lint, commit.**

### Task 5.2: The configuration file, checked by the real parser

**Files:**
- Modify: `var/tmp/helpers/layer_prune/cfgfile.py`
- Create: `tests/python/test_layer_prune_cfgfile.py`
- Modify: `tests/integration/layer_prune_observer.sh` (the parser check)

**Interfaces:**
- Produces: `cfgfile.render(policy)` emitting sections in the order `[read]`, `[execute]`, `[write]`, `[create]`, `[create-ipc]`, `[create-symlink]`, `[delete]`, `[restructure]`, `[connect]`, `[bind]`, `[limits]`, paths sorted, LF, final newline, and refusing (raising `ValueError`) a relative path, a path holding `*`, `?`, `[`, `\r` or `\n`, or a nested strict subset; `cfgfile.remainder(exercise: Policy, base: Policy) -> Policy`.

- [ ] **Step 1: Failing unit tests** for each refusal and for `remainder` (an entry whose sections are covered by the base's union along its ancestors is dropped; a new right on a base path stays).
- [ ] **Step 2: Failing integration check**: render a policy in Python inside the prune image and pass it to `phobos-policysystem.sh --config`; expect status 0 and a refused (status 11, `PHB-EPOLICY`) result for a hand-written nested strict subset, so the check proves the parser and the renderer agree in both directions.
- [ ] **Step 3: Implement, Step 4: pass, lint, commit.**

### Task 5.3: Grow loop, minimisation and the filesystem stage

**Files:**
- Create: `var/tmp/helpers/layer_prune/search.py`
- Create: `var/tmp/helpers/layer_prune/stages.py`
- Create: `var/tmp/helpers/layer_prune/main.py` (the command line for the stages built so far: `python3 main.py --stage filesystem <lang>` prunes every exercise under `$TESTING_DIR/<lang>` (default `/srv/phobos-prune-exercises`) and writes `<lang>_<exercise>.cfg` into `$OUTPUT_DIR`; Tasks 6.1 and 7.1 add `network`, `limits` and `all`, Task 8.1 the record, the stale-artefact removal and the exit contract)
- Create: `tests/python/test_layer_prune_search.py`
- Create: `tests/integration/layer-prune-fixture/build_script.sh`
- Create: `tests/integration/layer_prune.sh`
- Modify: `.github/workflows/build.yml` (run `layer_prune.sh` in the prune image)

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `search.ddmin(items: list[T], passes: Callable[[list[T]], bool], budget: int) -> tuple[list[T], bool]` returning the kept items and whether the budget sufficed.
  - `search.grow(run: Callable[[Policy], RunResult], seed: Policy, reference: Verdict, rounds: int, derive: Callable[[RunResult], dict[str, frozenset[str]]]) -> Policy` raising `PruneAbort(reason: str, evidence: dict)`.
  - `stages.prune_filesystem(exercise: Exercise, reference: Verdict, budget: Budget) -> tuple[Policy, list[dict]]`.
  - `stages.Budget(grow_rounds: int = 40, network_rounds: int = 10, minimise_runs: int = 150, verification_runs: int = 3, run_seconds: int = 1800)`.

- [ ] **Step 1: Failing unit tests for `ddmin` and `grow`** with synthetic oracles:

```python
def test_ddmin_keeps_exactly_the_needed_items():
    needed = {"b", "e"}
    kept, finished = search.ddmin(list("abcdefgh"), lambda subset: needed <= set(subset), budget=100)
    assert set(kept) == needed
    assert finished


def test_ddmin_out_of_budget_keeps_everything_it_could_not_try_permissively():
    kept, finished = search.ddmin(list("abcdefgh"), lambda subset: {"b"} <= set(subset), budget=1)
    assert "b" in kept
    assert not finished


def test_grow_aborts_on_a_failure_without_a_denial():
    with pytest.raises(search.PruneAbort, match="without an attributable denial"):
        search.grow(run=always_fails_without_denial, seed=empty_policy(), reference=passing(), rounds=5, derive=no_grants)


def test_grow_withdraws_a_grant_that_did_not_take_effect_and_aborts():
    with pytest.raises(search.PruneAbort, match="survived its own grant"):
        search.grow(run=refuses_the_same_object_after_the_grant, seed=empty_policy(), reference=passing(), rounds=5, derive=grant_everything)


def test_grow_stops_when_the_verdict_matches_and_leaves_harmless_denials_ungranted():
    policy = search.grow(run=passes_with_a_harmless_denial, seed=empty_policy(), reference=passing(), rounds=5, derive=grant_everything)
    assert policy.fs == {}
```

- [ ] **Step 2: Fail. Step 3: Implement** `search.py` (Zeller's ddmin over (path, section) pairs, counting runs against the budget) and `stages.prune_filesystem` exactly as A.6.4's stage 1. **Step 4: Pass, lint.**
- [ ] **Step 5: Write the fixture.** `build_script.sh` (bash, `set -u`) reads `/srv/prune-fixture/needed/data.txt`, tries `/srv/prune-fixture/optional/maybe.txt` and ignores failure, writes `build/out.txt`, creates `build/tmp/$RANDOM.tmp`, and writes `build/test-results/test/TEST-fixture.xml` with testcase `Fixture.readsNeeded` passing only when the needed read worked and `Fixture.writesOutput` passing only when the write worked. Variants by environment: `FIXTURE_FLAKY=1` fails `readsNeeded` on every second run (a counter file under `/var/tmp/layer-prune-counter`, outside the exercise copy), `FIXTURE_NO_SOURCE=1` prints `> Task :compileJava NO-SOURCE` and writes no report, `FIXTURE_SETSID=1` runs `setsid true` and fails when it fails.
- [ ] **Step 6: Write `tests/integration/layer_prune.sh`**: builds `/srv/prune-fixture/{needed,optional,unneeded}` and the sibling `/srv/prune-fixture-secret`, copies the fixture into `/srv/phobos-prune-exercises/java/fixture`, runs `python3 /var/tmp/helpers/layer_prune/main.py --stage filesystem java`, then asserts:
  - permitted: `phobos.sh --config <derived> -- bash build_script.sh` writes a report in which both tests pass;
  - forbidden: under the derived configuration `probe read /srv/prune-fixture/unneeded/secret.txt`, `probe read /srv/prune-fixture/optional/maybe.txt` and `probe read /srv/prune-fixture-secret/x` each print `OP read ret=-1 errno=EACCES`, while `probe read /srv/prune-fixture/needed/data.txt` prints `ret=` non-negative;
  - rights: the derived configuration names `/var/tmp/testing-dir/build` (or an ancestor that existed) in `[create]` and does not name `/srv/prune-fixture/needed` in `[write]`, and `probe write /srv/prune-fixture/needed/data.txt` is refused;
  - wrong reason: each variant exits non-zero with its abort reason on stderr and writes no `java_fixture.cfg`.
- [ ] **Step 7: Run it in the prune image**: `docker run --rm --network none --memory 3g --pids-limit 1024 -v "$PWD:/repo:ro" --entrypoint bash phobos-prune-layers:local -c 'cp -R /repo /work && cd /work && cp -R var/tmp/helpers /var/tmp/helpers && bash tests/integration/layer_prune.sh'`. Expected: `N passed, 0 failed`.
- [ ] **Step 8: Wire into `build.yml`, lint, commit** every path explicitly.

## PR 6: The network stage

### Task 6.1: Network rules from denials

**Files:**
- Create: `var/tmp/helpers/layer_prune/network.py`
- Create: `tests/python/test_layer_prune_network.py`
- Modify: `var/tmp/helpers/layer_prune/stages.py` (`prune_network`)
- Modify: `tests/integration/layer-prune-fixture/build_script.sh` (a loopback server and client, an optional external attempt, `FIXTURE_NEEDS_NET=1`)
- Modify: `tests/integration/layer_prune.sh`

**Interfaces:**
- Produces:
  - `network.bound_ports(trace: Trace) -> frozenset[tuple[str, int, str]]` (family, port, transport) from successful `bind`/`listen`/`getsockname` in the domain.
  - `network.NetworkDecision(connect: tuple[str, ...], bind: tuple[str, ...], refused_external: tuple[str, ...], reported: tuple[str, ...])`.
  - `network.network_rules(denials: list[Denial], bound: frozenset[tuple[str, int, str]], declared_hosts: tuple[str, ...]) -> NetworkDecision`.
  - `stages.prune_network(exercise, fs_policy, reference, budget) -> tuple[Policy, list[dict]]`.

- [ ] **Step 1: Failing tests.**

```python
def test_a_loopback_port_the_run_bound_becomes_the_loopback_wildcard():
    decision = network.network_rules([connect("127.0.0.1", 43521, "tcp")], frozenset({("AF_INET", 43521, "tcp")}), ())
    assert decision.connect == ("allow 127.0.0.1:*",)


def test_both_loopback_families_become_localhost():
    decision = network.network_rules([connect("127.0.0.1", 40000, "tcp"), connect("::1", 40001, "tcp")],
                                     frozenset({("AF_INET", 40000, "tcp"), ("AF_INET6", 40001, "tcp")}), ())
    assert decision.connect == ("allow localhost",)


def test_an_external_address_is_never_granted():
    decision = network.network_rules([connect("10.0.0.1", 80, "tcp")], frozenset(), ())
    assert decision.connect == ()
    assert decision.refused_external == ("10.0.0.1:80 tcp",)


def test_a_refused_ephemeral_bind_becomes_allow_zero():
    decision = network.network_rules([bind(0, "tcp")], frozenset(), ())
    assert decision.bind == ("allow 0",)


def test_a_refused_listen_on_an_unbound_socket_becomes_allow_zero():
    decision = network.network_rules([listen_unbound("tcp")], frozenset(), ())
    assert decision.bind == ("allow 0",)


def test_a_datagram_bind_on_port_zero_becomes_allow_zero_udp():
    decision = network.network_rules([bind(0, "udp")], frozenset(), ())
    assert decision.bind == ("allow 0 udp",)
```

- [ ] **Step 2: Fail. Step 3: Implement** as A.6.5 "Network"; `prune_network` runs A.6.4's stage 2 and then ddmin over the rules. **Step 4: Pass, lint.**
- [ ] **Step 5: Extend the fixture**: start `python3 -m http.server --bind 127.0.0.1 0` in the background, read its port from its output, fetch from it with `bash`'s `/dev/tcp`, and make `Fixture.talksToItsServer` depend on it; attempt `10.0.0.1:80` and ignore the result; `FIXTURE_NEEDS_NET=1` makes a test depend on the external attempt.
- [ ] **Step 6: Extend the suite**, both directions: permitted, the derived configuration carries `allow 127.0.0.1:*` and `allow 0` and the fixture's loopback test passes under it; forbidden, `probe connect 10.0.0.1 80` prints `errno=EACCES` under it and `probe bind 8080` is refused; wrong reason, `FIXTURE_NEEDS_NET=1` aborts with "needs external network".
- [ ] **Step 7: Run in the prune image, lint, commit.**

## PR 7: The limits stage

### Task 7.1: Sampler, margins and limit signatures

**Files:**
- Create: `var/tmp/helpers/layer_prune/sampler.py`
- Create: `var/tmp/helpers/layer_prune/limits.py`
- Create: `tests/python/test_layer_prune_limits.py`
- Modify: `var/tmp/helpers/layer_prune/runner.py` (sampling while a run is in progress, subreaper)
- Modify: `var/tmp/helpers/layer_prune/stages.py` (`prune_limits`)
- Modify: `tests/integration/layer_prune.sh`

**Interfaces:**
- Produces:
  - `limits.Measurement(wall_seconds: float, cpu_seconds: float, vm_peak_mb: float, tasks: int, highest_descriptor: int, largest_file_mb: float)`.
  - `limits.Margins(...)` with the defaults of A.6.5 as fields, one per line.
  - `limits.margins(measurements: list[Measurement], margins: Margins) -> dict[str, int]` returning keys `timeout`, `cpu`, `mem_mb`, `nproc`, `nofile`, `fsize_mb`.
  - `limits.limit_signature(status: int, last_samples: list[dict], limits: dict[str, int], diagnosis: list[Denial], control: list[Denial]) -> str | None`.
  - `sampler.Sampler(root_pid: int, uid: int, interval: float = 0.1)` with `start()`, `stop() -> list[dict]`.

- [ ] **Step 1: Failing tests.**

```python
def test_margins_take_the_maximum_over_runs_and_round_up():
    result = limits.margins([measurement(wall=41.0, cpu=30.2, vm=2100.0, tasks=70, fd=180, file=3.0),
                             measurement(wall=47.5, cpu=28.0, vm=2300.0, tasks=75, fd=150, file=2.0)], limits.Margins())
    assert result == {"timeout": 150, "cpu": 100, "mem_mb": 3584, "nproc": 166, "nofile": 362, "fsize_mb": 16}


def test_status_fourteen_is_the_timeout():
    assert limits.limit_signature(14, [], {"timeout": 60}, [], []) == "timeout"


def test_sigxfsz_is_the_file_size():
    assert limits.limit_signature(153, [], {"fsize_mb": 16}, [], []) == "fsize_mb"


def test_sigkill_near_the_cpu_limit_is_the_cpu_limit():
    samples = [{"pid": 9, "cpu_seconds": 99.4}]
    assert limits.limit_signature(137, samples, {"cpu": 100}, [], []) == "cpu"


def test_sigkill_far_from_the_cpu_limit_is_not_a_phobos_limit():
    samples = [{"pid": 9, "cpu_seconds": 12.0}]
    assert limits.limit_signature(137, samples, {"cpu": 100}, [], []) is None


def test_enomem_counts_only_when_the_unlimited_run_did_not_also_see_it():
    seen_in_both = [limit_denial("mmap", "ENOMEM")]
    assert limits.limit_signature(1, [], {"mem_mb": 512}, seen_in_both, seen_in_both) is None
    assert limits.limit_signature(1, [], {"mem_mb": 512}, seen_in_both, []) == "mem_mb"
```

(The expected numbers follow A.6.5: wall 47.5 x 3 = 142.5, rounded up to 150; cpu 30.2 x 3 = 90.6, to 100; VmPeak 2300 x 1.5 = 3450, to 3584; tasks 2 x 75 + 16 = 166; descriptors 2 x 181 = 362; file 2 x 3 = 6, floor 16.)

- [ ] **Step 2: Fail. Step 3: Implement**; the sampler reads `/proc/<pid>/status` (`VmPeak`, `Uid`), `/proc/<pid>/stat` (fields 14 and 15 divided by `os.sysconf("SC_CLK_TCK")`), `/proc/<pid>/fd` and `/proc/<pid>/task`, walking descendants by `/proc/<pid>/task/*/children`; the subreaper is `ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)` (`PR_SET_CHILD_SUBREAPER`, named as a constant). **Step 4: Pass, lint.**
- [ ] **Step 5: Extend the suite**, both directions: permitted, the fixture passes under the derived limits; forbidden, each derived limit is lower than its default in `phobos-constants.sh`, and under the derived configuration `probe` exceeding `nofile` prints `errno=EMFILE`, exceeding `fsize_mb` ends with status 153, and a `sleep` longer than the derived timeout ends with status 14.
- [ ] **Step 6: Run in the prune image, lint, commit.**

### Task 7.2: Joint verification and containment checks

**Files:**
- Create: `var/tmp/helpers/layer_prune/containment.py`
- Modify: `var/tmp/helpers/layer_prune/stages.py` (`verify`, `prune_exercise`)
- Create: `tests/python/test_layer_prune_containment.py`
- Modify: `tests/integration/layer_prune.sh`
- Modify: `docker/prune_phase/layers/Dockerfile` (compile `tests/integration/protection-matrix/probe.c` into `/usr/local/libexec/phobos-prune-probe` in a build stage; the probe is a test tool, not part of the grading image)

**Interfaces:**
- Consumes: `run_layers`, `Policy`, the probe's `OP <name> ret=<n> errno=<NAME>` lines.
- Produces:
  - `containment.CANARIES = ("/srv/phobos-prune-canary/secret", "/root/phobos-prune-canary")`, created by `containment.plant_canaries()` before the baseline.
  - `containment.checks(policy: Policy) -> list[ContainmentCheck]`, where `ContainmentCheck(name: str, probe_arguments: tuple[str, ...], must_fail_with: frozenset[str])`: each canary read, a write into one `[read]`-only path of the policy, `connect 10.0.0.1 80` (unless named), `bind 8080` (unless named), and one probe per derived limit.
  - `containment.run_checks(policy: Policy) -> list[dict]` raising `search.PruneAbort("containment check passed: <name>")` when a check that must fail succeeds.
  - `stages.verify(exercise, policy, reference, budget) -> list[dict]` implementing A.6.4's stage 4 with the diagnosis routing.

- [ ] **Step 1: Failing tests**: `checks` names every canary; a policy granting `/srv` makes `checks` still include the canary read and `run_checks` (with a fake probe that reports success) abort; a policy naming `allow 10.0.0.1:80` omits the connect check; `verify` routes a filesystem denial in a failing verification back to `prune_filesystem` at most twice and then aborts.
- [ ] **Step 2: Fail. Step 3: Implement. Step 4: Pass, lint.**
- [ ] **Step 5: Extend the suite**: run the full pipeline (`main.py --stage all java`) on the fixture; assert the record lists every containment check with `errno=EACCES` (or the limit's errno or status), and that a policy hand-edited to grant `/srv` makes the pipeline abort with "containment check passed".
- [ ] **Step 6: Run in the prune image, lint, commit.**

## PR 8: Switch the producer and the orchestrator

### Task 8.1: The per-language entry point and the artefacts

**Files:**
- Modify: `var/tmp/helpers/layer_prune/main.py`
- Modify: `docker/prune_phase/layers/Dockerfile` (`ENTRYPOINT ["python3", "/var/tmp/helpers/layer_prune/main.py"]`)
- Modify: `docker-compose.yaml` (service `prune_java` builds `docker/prune_phase/layers` with `RUN_PHASE_IMAGE`, `network_mode: none`, no capability, no privilege, and the three mounts of A.6.1 instead of the whole `./var/tmp`)
- Create: `tests/python/test_layer_prune_main.py`

**Interfaces:**
- Produces: `python3 main.py [--verbose] [--stage filesystem|network|limits|all] <lang>` writing `<lang>_<exercise>.cfg` and `<lang>_<exercise>.json` (schema 2, A.9) into `$OUTPUT_DIR` (default `/var/tmp/path_sets`), removing this language's earlier artefacts first (as `run_minimal_fs_all.sh` does), exiting non-zero when any exercise aborted and naming each.

- [ ] Steps: failing tests for artefact names, stale removal, the record's SHA-256 of the `.cfg`, and the non-zero exit naming an aborted exercise; implement; pass; lint; commit.

### Task 8.2: The orchestrator merges configurations

**Files:**
- Modify: `docker/prune_phase/orchestrate/orchestrate.py`
- Modify: `tests/python/test_orchestrate.py`
- Modify: `tests/python/test_orchestrate_helpers.py`
- Modify: `docker-compose.yaml` (orchestrator reads `.cfg` artefacts; a final `verify` service runs `main.py --verify java` in the prune image against the merged base)

**Interfaces:**
- Consumes: `<lang>_<exercise>.cfg` and `.json`.
- Produces: `BaseLanguage-<lang>.cfg` (union, hierarchy-normalised, no `[limits]`), `exercises/<lang>_<exercise>.cfg` (remainder plus `[limits]`), `TailPhobos.cfg`, the `debug/` comparisons; `artefact_disagreements` now compares the record's `cfg_sha256` with the `.cfg` beside it.

- [ ] Steps: failing tests (union of two exercise configurations, remainder drops covered entries and keeps new rights, `[limits]` never in the base, a hash mismatch refuses the merge); implement by reading sections with one small parser shared with `cfgfile.py` (import it from `var/tmp/helpers/layer_prune/cfgfile.py` by adding `--helpers-dir` to `sys.path`, which the orchestrator already takes as an option); pass; lint; commit.

### Task 8.3: Documentation

**Files:**
- Modify: `README.md`, `CLAUDE.md`, `AGENTS.md`, `SECURITY.md`, `var/tmp/pruning/orchestrate_core_idea.txt`, the `orchestrate.py` docstring.

- [ ] Steps: write the changes listed in A.12; check every command quoted in them by running it; `ec --no-color`; commit the files by name.

### Task 8.4: Prune the Maven reference exercise

Runs only once pull request 5 of the Ares 2 import plan (the exercise, defined in its A.4.3) is on `main` (Part B, ordering). Its output is that plan's Maven base.

**Files:**
- Modify: `docker-compose.yaml` (service `prune_java_maven`: the same build, mounts, `network_mode: none` and absence of any capability or privilege as `prune_java` from Task 8.1, with `command: ["--stage", "all", "java-maven"]`; the `orchestrate` service gains `java-maven` in `--langs` and a `depends_on` on `prune_java_maven`)

**Interfaces:**
- Consumes: the exercise at `var/tmp/testing-dir/java-maven/maven-reference/` and its `prune.json` (A.6.8); `main.py` (Task 8.1); the orchestrator (Task 8.2); the Maven verdict lines (Task 4.1).
- Produces: `var/tmp/path_sets/java-maven_maven-reference.cfg` and `.json`, and `var/tmp/opt/core/config/BaseLanguage-java-maven.cfg`, which the other plan's pull request 6 adopts unedited. Nothing under `core/` changes here.

- [ ] **Step 1: Check the precondition.** `git log --oneline origin/main -- var/tmp/testing-dir/java-maven/maven-reference` names the other plan's pull request 5; otherwise stop, since the task has no input.
- [ ] **Step 2: Add the compose service** and the orchestrator change; `yamllint --strict .`.
- [ ] **Step 3: Run the prune**, from the repository root, in an ordinary container as compose starts it: `docker compose -f docker-compose.yaml run --rm --build prune_java_maven`, then `docker compose -f docker-compose.yaml run --rm --no-deps orchestrate --langs java-maven --path-dir /var/tmp/path_sets --skip-prune`; `--no-deps` keeps `run` from starting `orchestrate`'s dependencies, which would prune the exercise a second time instead of reading the artefacts just written. The stages are those of A.6.4, unchanged: the three unsandboxed baseline runs, the permissive layered run, filesystem, network and limits, the joint verification and the containment checks. Expected: status 0, the two artefacts and the base.
- [ ] **Step 4: Read the result, not the status.** In `java-maven_maven-reference.json`: the baseline holds both test cases of the exercise, passed, in all three runs, with `tests_ran` true and neither `no_source` nor `infra_failure`; the permissive layered run reports no fixed-rule refusal; every containment check is refused; the widening list says how `/root/.m2/repository` is covered (`/root` is a fine-grained root, A.6.5, so grants there are per file or compacted beneath it, and an artefact the reference never loads stays ungranted, which the other plan records as its question R3); and no write-class right is granted under `/root/.m2`, since an offline run was measured writing nothing there. A write-class grant there is not a failure of this task, but it is a finding the adopting pull request has to explain.
- [ ] **Step 5: Wrong reasons, both directions.** On two throwaway copies of the exercise under another key (`java-maven-check`), never committed: without `test/`, the baseline aborts with `no_source` and no `.cfg` is written; with `junit-jupiter` pinned to a version the seeded repository lacks, the baseline aborts as an infrastructure failure with the offline line of A.8 and no `.cfg` is written. Meanwhile the unmodified exercise in Step 3 produced its `.cfg`, which is the permitted direction.
- [ ] **Step 6: Commit** `docker-compose.yaml` by name: `Prune the Maven reference exercise under its own key`. The artefacts are not committed by this task (`/var/tmp/path_sets/` is ignored, and the orchestrator's output under `var/tmp/opt/core/config` stays untracked); the record and the base are attached to this pull request and handed to the other plan's pull request 6.

## PR 9: Retire the Bubblewrap pruner

Only after Q5 is answered (Python), since the Python prune image still uses Bubblewrap until then.

**Files:**
- Delete: `var/tmp/pruning/detect_minimal_fs.sh`, `var/tmp/pruning/run_minimal_fs_all.sh`, `var/tmp/helpers/emit_artifacts.py`, `var/tmp/helpers/make_lang_sets.py` (if PR 8 no longer calls it), `docker/prune_phase/java/Dockerfile`, `tests/integration/prune_sandbox.sh`, `tests/integration/prune_producer.sh`, `tests/python/test_make_lang_sets.py` (with its helper)
- Modify: `.github/workflows/test.yml` (drop the Bubblewrap install step and the two suites), `.github/workflows/runner-capabilities.yml` and `tests/runner-capability-probe.sh` (drop `--assert-bwrap`), README, CLAUDE.md

- [ ] Steps: delete; run every remaining suite and the full lint set; grep for `bwrap`, `bubblewrap`, `detect_minimal_fs`, `run_minimal_fs_all`, `emit_artifacts` and resolve every hit; commit the files by name.

---

# Part C: Review record

An independent reviewer read this plan against the code it cites, in three rounds, and signed off explicitly in the third ("I approve the plan", with no remaining blocking concerns).

Round 1 raised six points, all acted on:

| Severity | Point | Resolution |
| --- | --- | --- |
| high | an exit status was treated as proof of which limit ended a run | A.6.5: a status is evidence only; a raise needs the limits-off control to have passed, a matching signature and a passing raised value; at most three doublings |
| high | an `EACCES`/`EPERM` may come from DAC, AppArmor or seccomp rather than a layer | A.6.3: `EPERM` on a path call is never granted, and a grant that does not make its own denial disappear is withdrawn and the exercise aborted (Task 5.3 test) |
| high | generalising to directories widens the sandbox | partly disagreed (a sibling cannot be proven denied under a directory grant, and per-file grants would fail correct solutions); write-class rights are now never widened, only `[read]`/`[execute]` outside fine-grained roots, and every widening is listed in the record (A.6.5, A.7, Q7) |
| medium | no mandatory acceptance gate for generated configurations | A.6.4: every candidate passes `phobos-policysystem.sh` before it is run or written; a run Phobos itself stopped is a pruner defect, never a verdict (Task 4.2 tests) |
| medium | networked verification of declared hosts not isolated | A.6.5: a separate opt-in service that only confirms or refuses declared rules; default services stay `network_mode: none` |
| low | generated configurations proven only in the permitted direction | A.6.4 and Task 7.2: containment checks with canaries, a `[read]`-only write, an unnamed destination and port, and each derived limit |

Round 2 approved, with one low note on the status contract. Acting on it showed that `phobos.sh` passes the command's own status through, so `2`, `11`, `15` and `125` count as a Phobos stop only together with Phobos's own stderr marker (A.6.4, Task 4.2). Two further gaps found while re-reading were fixed in the same round: the exercise sources move out of `/var/tmp/testing-dir`, which the exercise itself now occupies (A.6.1), and `main.py` is created where it is first used (Task 5.3). Round 3 approved all three changes.

A later revision added the Maven reference exercise as an input (A.6.8, the Maven lines of A.8 and Task 4.1, the stale-report refusal of Task 4.2, Task 8.4 and the ordering against the Ares 2 import plan of pull request 163). It was reviewed together with the matching changes to that plan in three rounds: this plan stopped repeating the exercise's build command, which that plan's A.4.3 defines, A.8 now says that under the layers the offline line classifies nothing, and Task 8.4 runs the orchestrator with `--no-deps` so that it does not prune the exercise a second time. The reviewer confirmed the ordering between the two plans has no cycle and approved explicitly: "I approve, no remaining concerns."
