# Denial Reporting Implementation Plan

> **How to execute:** work through Part B one task at a time, test first, with a review between tasks. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every Phobos layer prints, on standard error, one line for every distinct action it blocks, in the format `Phobos Security Error: the program tried to illegally <verb> the <Object> but was blocked by Phobos.`, within the limits stated in A.7 and A.10, and never grants anything or changes the outcome of a call while its supervisor runs.

**Architecture:** One seccomp user-notification supervisor per run. When the network layer is on, the existing connect guard is that supervisor and gains report-only traps on the path system calls; when it is off, the filesystem layer starts a small report-only supervisor of its own. The supervisor arms itself when the filesystem layer's Landlock enforcer calls `landlock_restrict_self`, reads the exact rules from that enforcer's own command line, mirrors the Landlock decision for each trapped call purely to decide whether to print, and always answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, so Landlock alone decides. The timeout and resource layers print their own line from the run's exit status.

**Tech Stack:** C23 (gcc-14, static PIE, built in the run-phase image), bash for the layers, the repository's shell harness and C unit suites, Docker for every Linux test.

**Spec:** Part A of this document. Like the other plan pull requests, the design and the tasks travel in one file; Part B argues from Part A. The measured spike lives beside it in `docs/superpowers/plans/2026-10-05-denial-reporting-spike/`.

## Global Constraints

- British English in all prose, comments, messages, workflow and step names.
- No em dashes; prefer a comma, a full stop or brackets over a hyphen.
- One variable, field or function declaration per line, in every language.
- Every text file LF, final newline, spaces not tabs.
- No `--privileged`, `--cap-add` or `--security-opt` for any suite, spike or run.
- The reporter never grants anything and, while its supervisor runs, never changes the outcome of a call: every notification on a report trap is answered with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, error 0, value 0. Enforcement stays with Landlock, the connect guard's existing decisions, the group lock and the rlimits. If a supervisor dies, the remaining trapped calls of the run fail closed with `ENOSYS`, the property the connect guard already has today (A.5.6).
- The output contract is one line per distinct blocked action (verb, noun and object), at most 100 lines per supervisor, and a closing summary that counts the network and filesystem refusals the supervisor judged while it supervised the command (A.7); the timeout and resource layers print their own single line and are not part of that count.
- A report trap never names a system call the connect guard enforces (`socket`, `connect`, `listen`, `sendto`, `sendmsg`, `sendmmsg`), nor one any filter refuses with `SECCOMP_RET_ERRNO`.
- The fixed parts of a message are byte-exact: the prefix `Phobos Security Error: the program tried to illegally ` and the suffix ` but was blocked by Phobos.`
- Every path in a message is quoted the way bash `${value@Q}` quotes it under `LC_ALL=C`, so no control byte and no byte outside printable ASCII reaches the terminal raw.
- Nothing language specific in `core/`.
- Every function in `core/*.sh` and `core/phobos-tools-*/*.sh` carries its comment; no comments inside function bodies.
- The guard's unit suite holds every line of every guard source to 100 % coverage, and the new reporter sources join that gate.
- Branch names use an allowed prefix (`feature/`, `ci/`, `docs/`).

---

# Part A: Design

## A.1 The request

Markus specified the line every layer prints for every action it blocks:

`Phobos Security Error: the program tried to illegally <read/write/execute/create/delete/connect/bind/...> the <File .../ Endpoint .../ ...> but was blocked by Phobos.`

The decided mechanism is "way 2": a supervisor traps the file system calls with a seccomp user-notification filter, reads the path out of the command, resolves it, mirrors the Landlock decision only to decide whether to report, and lets the kernel decide by continuing the call. It must work with the network restriction switched off (`-nnr`) and with every other combination of switches in which the filesystem layer is on. A program may repeat a refused action in a loop, so repetitions are de-duplicated and counted (A.7).

## A.2 What Phobos reports today

- **Filesystem.** Nothing per access. Landlock refuses silently (`EACCES`, `EXDEV`). After the command, `phobos-filesystem.sh` prints `Sandbox denials: network=N, filesystem=N. (PHB-EDENY)` from `count_denials` in `core/phobos-tools-common/phobos-log.sh`, which counts lines of the command's own standard error that match `Permission denied|EACCES|EROFS` or `EAI_AGAIN|EAI_FAIL|EAI_NONAME|Network is unreachable|Connection timed out`. It counts the program's wording, not Phobos's decisions: a swallowed denial is missed, a repeated message is counted every time, a network refusal printed as "Permission denied" is counted as filesystem, and a test that prints "Permission denied" on purpose is counted too.
- **Network.** The connect guard (`core/phobos-seccomp-networksystem/`) knows every refusal it makes, but says so only with `--verbose` (from `--debug`), as `[phobos-seccomp-networksystem] refusing ...` lines that name the port, the descriptor or the reason.
- **Bind.** The Landlock port rules of the network layer refuse a `bind` silently.
- **Timeout.** `phobos-timeoutsystem.sh` prints `Timed out after Ns. (PHB-ETIMEOUT)` and ends with status 14.
- **Resources.** Nothing. A command killed by `SIGXCPU` or `SIGXFSZ` ends with status 152 or 153 and no word from Phobos.

## A.3 Mechanisms evaluated

The constraint is AGENTS.md's: an ordinary container, no capability, Docker's default seccomp profile. PR 162 measured the observation side in the same environment (Docker 29.8.1, kernel 7.0.14-linuxkit aarch64, Landlock ABI 8); its findings are reused rather than repeated, and the decisive ones were re-measured here (A.4).

| Mechanism | What it sees | Privilege | Verdict for reporting |
| --- | --- | --- | --- |
| seccomp user notification plus `CONTINUE` | the call and its arguments before the kernel runs it, never the result | none beyond `no_new_privs` | **chosen**, with a mirror of the Landlock decision |
| Report on return (`EACCES`), through ptrace (`PTRACE_SYSCALL` or `SECCOMP_RET_TRACE` plus the exit stop) | the call and the kernel's actual answer | none, `ptrace_scope` at most 1 | rejected for the grading path, see below |
| Landlock audit (ABI 7) | the exact blocker and object | `CAP_AUDIT_READ` in the initial namespaces | not readable in a container (PR 162 measured `EPERM`) |
| fanotify | accesses that happened | `CAP_SYS_ADMIN` for permission events | sees no refusal at all |
| `LD_PRELOAD` | libc calls | none | blind to static binaries and raw calls, language dependent |
| eBPF, BPF LSM | everything | `CAP_BPF`, `lsm=bpf`, `bpf(2)` blocked by Docker | not available |
| the command's own standard error | the program's wording | none | the heuristic described in A.2 |

**Why not report on return.** Seeing the real `EACCES` is the one thing the chosen mechanism cannot do, so it was evaluated honestly:

- An `EACCES` alone does not attribute: discretionary permissions, a read-only mount or AppArmor return the same number, so a mirror is needed anyway to say "Phobos blocked this" rather than "the file mode did".
- Every traced call costs two stops (entry and exit) instead of one notification.
- ptrace changes what the command can do: a traced process cannot be traced again (a debugger, `strace`, a JVM attach or a sanitiser inside the submission fails), it shows a `TracerPid`, and the tracer has to handle signal-delivery and group stops for every thread of a JVM. That is a behaviour change on the grading path, which this feature must not have.
- PR 162 chose ptrace (`strace`) for the prune phase, where those costs are acceptable because the run is a measurement, not a grading. The two plans do not conflict: a pruning run under `strace` keeps the guard's listener working (PR 162 measured it), and the reporter adds one more notification per path call to such a run.

**Why `CONTINUE` is sound here.** `seccomp_unotify(2)` warns that `SECCOMP_USER_NOTIF_FLAG_CONTINUE` must not be used to make a security decision, because the kernel re-reads the arguments after the supervisor looked at them. The reporter makes no decision. It only ever continues, so a time-of-check, time-of-use race (another thread rewriting the path buffer, a symbolic link swapped, a directory renamed) can only make a message name the wrong object, or make it go missing. The kernel resolves the path itself after the continue and Landlock enforces on what it resolved.

## A.4 Measured facts (the spike)

Environment: Docker Desktop, kernel 7.0.14-linuxkit, aarch64, 6 vCPU, Landlock ABI 8, Docker's default seccomp profile, `--network none`, root in the container, no capability added, image `phobos-run-phase:ci`. The prototype is `docs/superpowers/plans/2026-10-05-denial-reporting-spike/denial-report-spike.c`, driven by `run-spike.sh` in the same folder; nothing of it is in `core/`.

### A.4.1 Facts that shaped the design

1. **Only one listener per filter tree.** A second `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, ...)` beneath an existing listener fails with `EBUSY` (`has_duplicate_listener` in `kernel/seccomp.c`). Measured twice: in-process (`first listener: ok`, `second listener: EBUSY`, a third filter without a listener: ok), and inside the real chain, where `phobos.sh -- spike --mode trap ...` fails with `seccomp NEW_LISTENER: Device or resource busy` whenever the network layer is on, and succeeds with `-nnr`. **A report-only filter can therefore not be stacked beneath the connect guard.** Whoever owns the listener must do both jobs.
2. **`unshare(CLONE_FILES)` is refused** by Docker's default profile (`EPERM`; `unshare` needs `CAP_SYS_ADMIN` there), so handing a listener over through a shared descriptor table is not available. `pidfd_getfd` is refused as well (the guard's own comment records it). The handoff is `SCM_RIGHTS` over a socket pair, as the guard does today.
3. **Filter counts in the real chain**, read from `Seccomp_filters` in `/proc/self/status` of the command: 1 with `-nnr -ntr` (Docker's own filter), 2 with `-nnr` (plus the group lock), 3 with `-ntr` (plus the guard's filter and its `sendmsg` lockout), 4 with every layer on.
4. **Arming and membership work.** The prototype traps `landlock_restrict_self`, arms on it, records the filter count, then the restricted process installs a no-op marker filter. A helper forked before the restriction (standing in for the filesystem layer's `tee` and counter) opened `/etc/hosts` fifty times, unrestricted, and produced no message; the command's own refused opens produced exactly one message each.
5. **`SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP`** (Linux 6.6, set with `SECCOMP_IOCTL_NOTIF_SET_FLAGS`) cuts a notification round trip from about 31 µs to about 2.3 µs on this machine. The CI kernels are 6.17 and 7.0.
6. **`process_vm_readv` and `/proc/<pid>/{cwd,fd,status,cmdline}`** work from the parent supervisor in the ordinary container. Yama is not present on this kernel; on a host with `ptrace_scope` 1 the supervisor is still an ancestor of every task it reads, except an orphan reparented to init (A.5.7).

### A.4.2 Overhead

Median of five interleaved repetitions; the rules are the shape of the shipped Java policy (system read and execute, `/tmp`, `/dev/null` and the Maven repository writable, `/proc` and `/sys` unnamed).

| Workload | plain | Landlock | trap, async | trap, sync | report, async | report, sync |
| --- | --- | --- | --- | --- | --- | --- |
| open, read 1 byte, close of a granted file (ns per round) | 1 375 | 1 532 | 32 855 | 3 815 | 46 937 | 10 788 |
| the same on a refused file (ns per round) | 1 429 | 894 | 30 543 | 2 956 | 46 185 | 10 753 |
| `javac` of 300 classes, about 690 trapped calls (s) | 0.443 | 0.444 | 0.505 | 0.469 | 0.529 | 0.480 |
| `mvn -o test`, 10 JUnit 5 classes, about 910 trapped calls (s) | 1.612 | 1.830 | 1.807 | 1.824 | 1.845 | 1.791 |

"trap" answers every notification with `CONTINUE` at once (the floor of the mechanism); "report" reads the path, resolves it, walks its ancestors by inode against the rules, de-duplicates and prints. "sync" sets `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP`.

Spread (minimum to maximum of the five runs, seconds): `javac` Landlock 0.422 to 0.455, report sync 0.447 to 0.489, report async 0.494 to 0.549; Maven plain 1.566 to 1.703, Landlock 1.673 to 1.916, report sync 1.702 to 1.918, report async 1.793 to 1.868. The file loops varied by less than 5 %. The Maven ranges of Landlock alone and of report sync overlap almost entirely, which is what "within the noise" means below.

What the reporter judged in those runs (aarch64 numbers): `javac` 683 `openat`, 7 `execve`, 1 `mkdirat`, 1 `unlinkat`, 1 `landlock_restrict_self`; Maven 840 `openat`, 17 `execve`, 29 `mkdirat`, 27 `unlinkat`, 1 `landlock_restrict_self`. The spike's mirror covers exactly those four calls, so on these workloads it did the full judgement for every notification; no rename, link, `mknodat`, `symlinkat`, `truncate` or `bind` occurred. Those calls cost one more resolution each (two for a rename) when they do occur, and they are rare in builds; the implementation's acceptance suite repeats the measurement with a workload that renames and links (Task 2.5).

Reading the numbers:

- A trapped path call costs about 2.3 µs more with synchronous wake-up, and the mirror adds about 7 µs on top (resolution with `realpath`, one `stat` per ancestor, one read of `/proc/<pid>/status`). On a loop that does nothing but open files that is 7 times slower; on the two build workloads measured it is 8 % for `javac` (0.480 s against 0.444 s under Landlock alone) and within the noise for the Maven build (1.791 s against 1.830 s). Five runs with their range are descriptive, not a statistical result, and they say nothing about other workloads; the shipped Java acceptance exercise is timed against `main` once the implementation exists (Task 3.2, Step 4).
- Without synchronous wake-up the same workloads cost 19 % (`javac`) and 1 % (Maven), and the file loop 30 times. Synchronous wake-up is therefore used wherever the kernel offers it, and its absence is reported once as a notice, not refused.
- A de-duplicated denial is not cheaper than an allowed call, because the mirror runs before the de-duplication; 100 000 refused opens of one file printed one line and counted 100 000.

### A.4.3 What a real Java run prints

Under the shape of the shipped Java policy the Maven run printed 17 distinct lines, every one a genuine refusal the JVM tolerates: `/proc/meminfo`, `/proc/cpuinfo`, `/proc/stat`, `/proc/mounts`, `/proc/cgroups`, `/proc/filesystems`, `/proc/sys/vm/overcommit_memory`, `/proc/net/if_inet6`, `/proc/self/coredump_filter` (write), `/proc/<pid>/stat` twice, `/proc/self/fd` (directory), `/sys/devices/system/cpu/online` and `possible`, two `/sys/kernel/mm/transparent_hugepage` files, and `/dev/tty` (write). They are true and they are noise for a student. See Q1.

## A.5 Architecture: one supervisor per run

### A.5.1 Who supervises, in every combination

| Timeout | Network | Filesystem | Supervisor | Reports |
| --- | --- | --- | --- | --- |
| on or off | on | on | the connect guard, started by the network layer with `--report-filesystem` | network refusals, bind ports, filesystem denials |
| on or off | on | off (`-nfr`) | the connect guard, without `--report-filesystem` | network refusals, bind ports |
| on or off | off (`-nnr`) | on | `phobos-seccomp-filesystem`, started by the filesystem layer | filesystem denials, including UNIX socket creation by `bind` |
| on or off | off | off | none | nothing is blocked by these two layers, so nothing is reported |

The timeout layer's group lock is a filter without a listener, so it never conflicts. `--no-restriction` runs nothing and reports nothing.

`phobos.sh` decides from its switches: it passes `--report-filesystem` to the network layer when the filesystem layer is on, and `--no-own-reporter` to the filesystem layer when the network layer is on. A standalone filesystem layer (`phobos-filesystem.sh --config ...`) starts its own reporter; a standalone network layer reports network refusals and bind ports only. If a reporter is started beneath a listener anyway (a wrong flag, a future layer), its child gets `EBUSY`, prints one notice and runs the rest of the chain without a filter: reporting is lost, enforcement is not touched.

### A.5.2 How the filters stack

The kernel runs every filter of a task on every call, from the newest to the oldest, and takes the action with the highest precedence: `KILL_PROCESS`, `KILL_THREAD`, `TRAP`, `ERRNO`, `USER_NOTIF`, `TRACE`, `LOG`, `ALLOW`. Between two filters that return the same action, the newest wins (`seccomp_run_filters` keeps the first match it meets while walking from the newest). Consequences for this design:

- Because only one listener may exist (A.4.1), there is never a second `USER_NOTIF` filter to compete with; the question of which listener wins does not arise. The report traps are simply added to the one filter that has the listener.
- Any `ERRNO` from any filter beats `USER_NOTIF`. Docker's refusals, the guard's refusal of non-native ABIs, of `io_uring_*`, of `setsid` and `setpgid`, and the group lock's refusal of `setsid` and `setpgid` all keep working unchanged and are never notified (A.10).
- The marker filter (A.5.3) returns `ALLOW` for everything and has no listener, so it changes no outcome.
- Order of installation in a full run: Docker, group lock (timeout layer), guard filter and its `sendmsg` lockout (network layer), marker (filesystem layer's enforcer, right after `landlock_restrict_self`). With `-nnr` the reporter's filter takes the guard's place.
- The report set never names a call the guard enforces (Global Constraints). In the guard's filter the enforcement traps come first and the report traps after them, but correctness does not rest on the order: the two sets are disjoint, and a unit test holds them disjoint.

### A.5.3 Arming and domain membership

The supervisor's filter is in force long before the filesystem Landlock domain exists. With the network layer on it covers the network layer's own enforcer, the filesystem layer's shell, its `tee`, the denial counter, the polling `sleep` of `run_forwarding_signals` and the resource layer, none of which is under the filesystem ruleset; with `-nnr` it covers the resource layer. Reporting their accesses against the filesystem rules would print false lines (`/var/tmp/opt/core/...` is not granted, yet the layers read it before the restriction). So:

1. **Arming.** The filter also traps `landlock_restrict_self`. The supervisor is told the enforcer's path (`--landlock-bin`, the same value the layers pass the enforcer) and runs a three-state machine over these notifications; every one of them is answered with `CONTINUE` whatever the state:

   | State | Notification from a caller whose `/proc/<pid>/exe` is the enforcer (both canonicalised) and whose `/proc/<pid>/cmdline` the enforcer's parser accepts | Any other `landlock_restrict_self` |
   | --- | --- | --- |
   | `UNARMED` | with `--no-filesystem`: build the bind model (A.8.2), go to `NETWORK_ARMED`; without: build the filesystem model, record the filter count, go to `FILESYSTEM_ARMED` | ignored |
   | `NETWORK_ARMED` | without `--no-filesystem`: build the filesystem model, record the filter count, go to `FILESYSTEM_ARMED`; with it again: ignored | ignored |
   | `FILESYSTEM_ARMED` | ignored | ignored |

   In a full run the network layer's enforcer arrives first and the filesystem layer's second, so both models arm in that order; with `-nnr` only the second arrives, with `-nfr` only the first. Once `FILESYSTEM_ARMED`, nothing re-arms, so the command cannot replace the model by running its own copy of the enforcer: it can only reach the enforcer after the filesystem enforcer armed the supervisor, since the command is started by that enforcer. The caller is blocked in the notification while the supervisor reads, so the command line is the one the enforcer just parsed and enforces; the enforcer never reaches `landlock_restrict_self` with a command line it rejected, so a rejection in the supervisor means the two parsers diverged, and the supervisor then disarms filesystem reporting with one notice instead of guessing. A full-chain case in `reporting.sh` (Task 3.2) shows both models armed, in that order, by a refused `bind` and a refused read in the same run.
2. **Membership.** The enforcer, given `--mark-reported-domain`, installs a no-op filter right after `landlock_restrict_self`. Seccomp filters are inherited by every fork, clone and exec and cannot be removed, so exactly the tasks of the filesystem domain carry one filter more than the count the supervisor recorded at arming. A notification is mirrored only when the task's `Seccomp_filters` is above that count. Tasks outside the domain are continued at once.

The test is sound under one invariant, which the plan states and tests rather than assumes: **no process outside the filesystem domain that runs under the supervisor's filter installs a seccomp filter of its own.** Those processes are all Phobos's own (the layer shells, `tee`, the counter until Task 4.3 removes it, `sleep`, the network layer's enforcer, the resource layer); the untrusted command runs entirely inside the domain and cannot put a process outside it. A helper that broke the invariant would only make the supervisor print wrong lines for it, never change a decision. Task 2.5 pins the invariant: during a run it reads `Seccomp_filters` of every process under the supervisor that is not a descendant of the enforcer and requires it to equal the count recorded at arming, and a test helper that does install a filter outside the domain shows what breaking it does (wrong lines, unchanged outcomes).

Rejected for membership: walking the parent chain to the arming process (an orphan reparented away is lost, and every new task costs a walk), a marker system call (a magic number in the command's syscall stream), and `personality` flags (they change behaviour).

### A.5.4 The mirror

The supervisor reproduces Landlock's question, "do the rules along this path grant every right this call needs", and nothing more:

- **Rules.** Parsed from the enforcer's command line by the enforcer's own parser, in a non-exiting form shared by both (Task 1.1). Each rule path is opened with the enforcer's own `open_flags_for_rule` and `fstat`ed to `(st_dev, st_ino)`, with the rights `rights_granted_for` gives and the directory-only rights removed from a file rule, exactly as `add_path_rule` does. The enforcer opened the same paths moments earlier and no untrusted code has run in between.
- **Handled rights.** `filesystem_rights_for_version` of the same ABI version, queried without the enforcer's minimum-version refusal. A right the kernel does not handle is never reported.
- **Resolution.** The path is read from the command with `process_vm_readv`, made absolute against `/proc/<pid>/cwd` or `/proc/<pid>/fd/<dirfd>`, and resolved with `realpath` (the object itself, or its parent for a call that creates or removes a name). The walk then `stat`s each ancestor of the resolved path up to `/` and unions the rights of every rule whose inode matches, which is Landlock's walk over dentries, including bind mounts reached through a rule's inode.
- **Which right.** A.6 maps every trapped call and flag combination to the rights Landlock checks, and to the one message it prints.

The model never decides anything. Where it is wrong, a message is wrong or missing.

**Deliberately not mirrored, and therefore never reported:** an `openat2` whose `resolve` field is not 0 (`RESOLVE_BENEATH`, `RESOLVE_IN_ROOT`, `RESOLVE_NO_SYMLINKS` and the rest change the walk in ways `realpath` does not reproduce); an `open` with `O_TMPFILE` (no name is created, and which right Landlock checks for it is not pinned by a test here); a path whose directory descriptor or working directory reads back as deleted or as not reachable from the root (`(deleted)` or `(unreachable)` in the link). These are silent by construction, so they err towards a missing line, never a wrong one. Every other row of A.6.4 is pinned against the kernel by an acceptance test in both directions.

**Truncation and older kernels.** Below Landlock ABI 3 the kernel does not handle `TRUNCATE` at all: `truncate(2)` is then not restricted by Landlock, and an `open` with `O_TRUNC` needs write access, which `WRITE_FILE` already governs. Masking the wanted rights with the handled rights of the running ABI therefore reproduces both ABIs; a unit case builds the model at version 2 and at version 3 and checks that a refused `truncate` is reported only at 3, and an `O_WRONLY|O_TRUNC` open without `w` at both.

### A.5.5 Placement: outside the Landlock domain and the rlimits

- **Guard as supervisor.** Unchanged: its parent half is forked before the network layer's ruleset, the filesystem ruleset and the rlimits exist.
- **Report-only supervisor.** The filesystem layer puts it in front of the resource layer: `phobos-seccomp-filesystem --landlock-bin <enforcer> -- [phobos-resourcesystem.sh SPEC --] phobos-landlock-filesystem-and-networksystem --mark-reported-domain ... -- COMMAND`. It forks before the resource layer sets the limits and before the enforcer applies Landlock, so the parent half is under neither. It sets `no_new_privs` in the child before installing the filter; the enforcer would set it a moment later anyway, so the command sees no difference.
- **Scoping.** The filesystem ruleset applies `LANDLOCK_SCOPE_SIGNAL`, so the command cannot signal the supervisor outside its domain. A command that kills it some other way (it cannot: it has no capability and is scoped) would only make its own trapped calls fail with `ENOSYS` (A.5.6).

### A.5.6 Lifetime and failure

- **Exit status.** The report-only supervisor forwards `SIGTERM`, `SIGHUP`, `SIGINT` and `SIGQUIT` to its child, reaps it and ends with the guard's `exit_code_from_status` mapping, the same number the filesystem layer saw before (128 plus the signal for a signalled command).
- **Leftover tasks.** When its direct child has ended, the report-only supervisor forks a drainer that keeps the listener, redirects its own standard error to `/dev/null`, answers every remaining notification with `CONTINUE` and ends when the kernel reports that no task is left, and then ends with the child's status itself. A daemon the command left behind therefore keeps working exactly as before and the run is not held open by it (today, with `-nnr`, it is not held open either). The guard keeps its current lifetime (it waits until no supervised task is left), which this plan does not change.
- **Supervisor gone.** If a supervisor dies while tasks remain, the kernel answers every trapped call of those tasks with `ENOSYS`, the granted ones included. That fails closed: nothing is granted that Landlock would refuse, but a reporter bug becomes an availability bug for the rest of that run, and the guarantee "changes no outcome" holds only while the supervisor runs. The connect guard has had exactly this property for `connect`, `socket`, `listen` and the sends since it was introduced; with the report traps it extends to the path calls. Of the mechanisms considered in A.3, only ptrace would avoid it, and ptrace was rejected because it changes what the command can do (A.3); every listener-based design has it, because only a live listener can continue a trapped call. The reporter is therefore small, allocates nothing per notification, and is covered by the same 100 % line gate as the guard; a test pins the `ENOSYS` behaviour (Task 2.5).
- **`CONTINUE` is preflighted.** A kernel can accept a listener filter (Linux 5.0) without knowing `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (Linux 5.5); a refused `CONTINUE` would leave the trapped call failed, which is exactly an outcome change. Both supervisors therefore add the report traps only when two checks pass, made before forking the command. First, `query_landlock_version()` answers 1 or more, since without Landlock there is no Landlock refusal to report. Second, `continue_supported()` proves `CONTINUE` directly rather than inferring it from the kernel version, because a vendor kernel can carry a Landlock backport on an older seccomp: it forks a throwaway probe child that sets `no_new_privs`, installs a listener filter trapping only `getppid`, hands the listener up over a socket pair and calls `getppid`; the supervisor waits at most one second for that one notification (`poll`), answers it with `CONTINUE`, and then closes the listener whatever happened, which releases a probe still waiting in its trapped call (it gets `ENOSYS`), so a refused `CONTINUE`, a lost notification or a timeout can never hang the check. The probe writes what its `getppid` returned and exits; the check passes only when the send succeeded and that value is the supervisor's own process number. Every other failure of the check is "unsupported" as well, never an exit: a socket pair or fork that fails, and a probe that cannot install its listener or hand it over (the supervisor's receive then sees the probe's end of the socket close), after which both socket ends are closed and the probe is reaped before the check returns false. The probe is reaped before anything else happens; it costs one fork per run. Measured in the spike: the real probe answered "supported" alone and under `phobos.sh -nnr`; a build of it that answers with an unknown flag instead of `CONTINUE` (the kernel then refuses the send with `EINVAL`, as an old kernel refuses `CONTINUE`) answered "unsupported" at once, its probe's `getppid` having returned `ENOSYS`, with no hang; and the probe run beneath the guard's listener (where its own listener is refused with `EBUSY`) answered "unsupported" with the probe reaped (status 3). When either check fails, the guard keeps exactly today's filter, the report-only supervisor installs no filter and runs the command, and either says once that reporting is off on this kernel. Unit cases drive each check to fail (the version query answering 0; the send answering `EINVAL` while the version query answers 8; `poll` timing out with no notification; the socket pair or the fork failing; the probe exiting before it hands a listener over) and check that the check returns false without exiting, every descriptor it opened is closed, the listener (when there was one) is closed before the probe's result is read, the probe is reaped, the guard's filter then equals today's and the report-only supervisor runs the command unsupervised.
- **Cannot start.** If the report-only supervisor's child cannot install its filter (`EBUSY` beneath another listener, or any other refusal of `seccomp`), it says so once and the run continues without reporting. A kernel without `CONTINUE` never reaches this point, because the preflight above already decided not to install a filter. A diagnostic is not made a new reason to refuse a grading run.

### A.5.7 Races and what they can do

- The path buffer, the working directory or a symbolic link can change between the supervisor's read and the kernel's own resolution after `CONTINUE`. Effect: a message names the wrong object, is missing, or appears for a call that ended up granted. Never an enforcement change, because the answer is always `CONTINUE`.
- The notification is checked with `SECCOMP_IOCTL_NOTIF_ID_VALID` after every read from the command, as the guard does, so a recycled process number cannot make the supervisor read a stranger's memory into a message.
- An orphan reparented to init is no longer a descendant of the supervisor. On a host with Yama `ptrace_scope` 1 `process_vm_readv` then fails and the message is missing.
- `io_uring` opens never pass through seccomp. With the network layer on, the guard refuses `io_uring` altogether; with `-nnr`, an `io_uring` open is enforced by Landlock and not reported.

## A.6 The message format

### A.6.1 Grammar

`Phobos Security Error: the program tried to illegally <verb phrase> the <Object noun> <object>[ <detail>] but was blocked by Phobos.`

- The verb phrase is lower case. It may carry its preposition ("connect to", "send to", "listen on"), because "connect the Endpoint" is not English; the fixed prefix and suffix stay byte-exact.
- The noun is capitalised, as in Markus's "File" and "Endpoint".
- A path is quoted exactly as bash 5.2 `${value@Q}` quotes it under `LC_ALL=C`, which is what the policy parser already does for a malformed configuration line (`${line@Q}` in `phobos-policy-parse.sh`): `'/etc/hostname'` when every byte is printable ASCII, a quote inside written as `'\''`; otherwise `$'...'` with `\'`, `\\`, `\a`, `\b`, `\t`, `\n`, `\v`, `\f`, `\r`, `\E` and three-digit octal for every other byte (`$'/\303\251'` for an é, `$'/del\177'`). The spike's quoting agrees with bash on 15 names covering every one of those cases (`denial-report-spike --quote`). A path longer than 1024 bytes is cut there before quoting and followed by ` (truncated)`.
- An endpoint is the output of the guard's endpoint formatter that PR 162's plan introduces (address and port, IPv6 bracketed, escaped; A.8.1), followed by ` over TCP` or ` over UDP`.
- When the path the program named differs from the path Landlock judged (a symbolic link, `..`, a relative name), the judged path is the object and the named one follows as ` (named as '...')`, because the judged path is what a policy would have to name.
- Each verb and noun pair names exactly one policy section, so a line tells the operator which section would have granted the action.

### A.6.2 Vocabulary

| Layer | Blocked action (Landlock right or guard decision) | Verb phrase | Object | Section that grants it |
| --- | --- | --- | --- | --- |
| filesystem | `READ_FILE` | read | the File `'p'` | `[read]` |
| filesystem | `READ_DIR` | read | the Directory `'p'` | `[read]` |
| filesystem | `WRITE_FILE`, `TRUNCATE` | write | the File `'p'` | `[write]` |
| filesystem | `EXECUTE`, and `READ_FILE` for an `execve` | execute | the File `'p'` | `[execute]` (and `[read]`) |
| filesystem | `MAKE_REG` | create | the File `'p'` | `[create]` |
| filesystem | `MAKE_DIR` | create | the Directory `'p'` | `[create]` |
| filesystem | `MAKE_SOCK` | create | the Socket File `'p'` | `[create-ipc]` |
| filesystem | `MAKE_FIFO` | create | the Named Pipe `'p'` | `[create-ipc]` |
| filesystem | `MAKE_SYM` | create | the Symbolic Link `'p'` | `[create-symlink]` |
| filesystem | `MAKE_CHAR`, `MAKE_BLOCK` | create | the Device `'p'` | none, never granted |
| filesystem | `REMOVE_FILE` | delete | the File `'p'` | `[delete]` |
| filesystem | `REMOVE_DIR` | delete | the Directory `'p'` | `[delete]` |
| filesystem | `REFER` on a rename | move | the File `'p'` to `'q'` (or the Directory) | `[restructure]` |
| filesystem | `REFER` on a hard link | link | the File `'p'` to `'q'` | `[restructure]` |
| network (guard) | a stream `connect` refused | connect to | the Endpoint `10.0.0.1:443 over TCP` | `[connect]` |
| network (guard) | a datagram `connect`, `sendto`, `sendmsg` or `sendmmsg` refused | send to | the Endpoint `10.0.0.53:53 over UDP` | `[connect] ... udp` |
| network (guard) | a `connect` to a UNIX socket refused | connect to | the Socket File `'p'` | none, the guard carries no UNIX family |
| network (guard) | a `socket` of a refused type | open | the Socket Type `raw (AF_INET, SOCK_RAW)` | none |
| network (guard) | a `listen` on a socket bound to no port refused | listen on | the Port chosen by the kernel over TCP | `[bind] allow 0` |
| network (Landlock, mirrored) | `BIND_TCP`, `BIND_UDP` | bind | the Port `8080 over TCP` | `[bind]` |
| timeout | the time limit expired | exceed | the Time Limit of `600` seconds | `--timeout` / `timeout` in a configuration |
| resources | `SIGXCPU` | exceed | the CPU Time Limit of `600` seconds | `cpu` |
| resources | `SIGXFSZ` | exceed | the File Size Limit of `256` MB | `fsize_mb` |

Examples, byte for byte:

```
Phobos Security Error: the program tried to illegally read the File '/etc/shadow' but was blocked by Phobos.
Phobos Security Error: the program tried to illegally create the Directory '/var/tmp/nope' but was blocked by Phobos.
Phobos Security Error: the program tried to illegally read the File $'/tmp/odd\nname' but was blocked by Phobos.
Phobos Security Error: the program tried to illegally read the File '/etc/locale.alias' (named as '/usr/share/locale/locale.alias') but was blocked by Phobos.
Phobos Security Error: the program tried to illegally connect to the Endpoint 93.184.216.34:443 over TCP but was blocked by Phobos.
Phobos Security Error: the program tried to illegally bind the Port 8080 over TCP but was blocked by Phobos.
Phobos Security Error: the program tried to illegally exceed the Time Limit of 600 seconds but was blocked by Phobos.
```

### A.6.3 One call, one line

A call Landlock refuses for more than one missing right prints one line, chosen by a fixed order that follows the kernel's own checks: for a rename, a missing `REMOVE_*` on the source's parent first, then `MAKE_*` on the destination's parent, then `REFER`; for an `open` that creates, `MAKE_REG` on the parent, then `WRITE_FILE` on the new file (Landlock creates the file and then refuses the open, a known Landlock behaviour, and the line says "write"); for an `open`, `WRITE_FILE` before `READ_FILE`; for an `execve`, "execute" whichever of `EXECUTE` and `READ_FILE` is missing.

### A.6.4 Mapping of trapped calls

| Calls (x86_64 legacy names in brackets) | Right checked | On |
| --- | --- | --- |
| `openat`, `openat2` (`open`, `creat`) without `O_PATH` | `READ_FILE` or `READ_DIR` for read access, `WRITE_FILE` for write access, `TRUNCATE` for `O_TRUNC` on an existing file, `MAKE_REG` for `O_CREAT` when the name does not exist | the file, or the parent when it is created |
| `execve`, `execveat` | `EXECUTE` and `READ_FILE` | the file |
| `mkdirat` (`mkdir`) | `MAKE_DIR` | the parent |
| `mknodat` (`mknod`) | `MAKE_REG`, `MAKE_FIFO`, `MAKE_SOCK`, `MAKE_CHAR` or `MAKE_BLOCK` by the mode | the parent |
| `unlinkat` (`unlink`, `rmdir`) | `REMOVE_FILE`, or `REMOVE_DIR` with `AT_REMOVEDIR` | the parent |
| `renameat2` (`rename`, `renameat`) | `REMOVE_*` on the source parent, `MAKE_*` on the destination parent, `REFER` when the parents differ; with `RENAME_EXCHANGE` the same in both directions | both parents |
| `linkat` (`link`) | `MAKE_REG` on the destination parent, `REFER` when the parents differ | the destination parent |
| `symlinkat` (`symlink`) | `MAKE_SYM` | the parent of the link |
| `truncate` | `TRUNCATE` | the file |
| `bind` with a `sockaddr_un` path | `MAKE_SOCK` | the parent |
| `bind` with `sockaddr_in` or `sockaddr_in6` | `BIND_TCP` or `BIND_UDP` from the network model; the transport comes from the guard's socket table, so the line is printed only when the guard is the supervisor (with `-nnr` there is no network ruleset to refuse a port anyway) | the port |
| `landlock_restrict_self` | none, arming only | |

**Supported flags, as a whitelist.** A trapped call is judged only when every flag it carries is in this list; any other flag, or any combination not listed, makes it silent (it errs towards a missing line), and a unit case per excluded flag pins that:

| Call | Judged with | Silent with |
| --- | --- | --- |
| `openat`, `open`, `creat` | any access mode, `O_CREAT`, `O_EXCL`, `O_TRUNC`, `O_APPEND`, `O_CLOEXEC`, `O_NONBLOCK`, `O_NOCTTY`, `O_DIRECTORY`, `O_NOFOLLOW`, `O_SYNC`, `O_DSYNC`, `O_LARGEFILE`, `O_DIRECT`, `O_ASYNC` | `O_PATH`, `O_TMPFILE`, `O_NOATIME` (it can fail with `EPERM` on ownership first), any other bit |
| `openat2` | as `openat`, with `resolve` 0 | any non-zero `resolve` |
| `execve`, `execveat` | `execveat` flags 0 or `AT_SYMLINK_NOFOLLOW` | `AT_EMPTY_PATH` |
| `mkdirat`, `mknodat`, `symlinkat`, `truncate` | always | |
| `unlinkat` | 0, `AT_REMOVEDIR` | any other bit |
| `renameat2`, `renameat`, `rename` | 0, `RENAME_NOREPLACE`, `RENAME_EXCHANGE` | `RENAME_WHITEOUT`, any other bit |
| `linkat`, `link` | 0 | `AT_SYMLINK_FOLLOW`, `AT_EMPTY_PATH` |
| `bind` | a `sockaddr_un` with a path, a `sockaddr_in`, a `sockaddr_in6` | an abstract UNIX name, any other family |

**Calls that fail before Landlock is asked are silent.** The kernel checks several things before the Landlock hook, and the mirror only reports when none of them would end the call first:

- the name must exist, unless the call creates it (`ENOENT` otherwise);
- a name that is created must not exist yet: `O_CREAT|O_EXCL`, `mkdirat`, `mknodat`, `symlinkat`, `linkat` and `RENAME_NOREPLACE` on an existing target end with `EEXIST` before Landlock (a plain `O_CREAT` on an existing file is an ordinary open of it);
- discretionary access control must allow the call. The supervisor starts with the command's credentials, but a privileged command (root in the container) can change its own with `setuid`, `setgroups` or `capset`, which `no_new_privs` does not prevent. So the supervisor first compares the task's `Uid`, `Gid` (all four of each), `Groups` and `CapEff` lines in `/proc/<pid>/status` with its own; when any differs it stays silent (it errs towards a missing line). When they are equal it asks `faccessat(..., AT_EACCESS)` for the access the call needs on the object, or write and search on the parent for a call that creates or removes a name, and stays silent when that is refused, since the refusal then is the file mode's, not Phobos's;
- a type mismatch (`O_DIRECTORY` on a file, `unlinkat` without `AT_REMOVEDIR` on a directory) ends with `ENOTDIR` or `EISDIR` first;
- a final symbolic link under `O_NOFOLLOW` (`openat`) or `AT_SYMLINK_NOFOLLOW` (`execveat`) ends with `ELOOP` first: when `lstat` shows the last component is a link, such a call is silent.

A call on a name that does not exist (and does not create it) is not reported: path lookup fails with `ENOENT` before Landlock is asked. `stat`, `access`, `readlink`, `chdir`, `chmod`, `chown`, `utimensat` and the extended attribute calls are not trapped, because Landlock checks no right for them. `ftruncate` is not trapped: `w` always grants `WRITE_FILE` and `TRUNCATE` together, so a descriptor that may be written may be shortened. `ioctl` is not trapped (A.10).

## A.7 Volume

The user-facing contract is therefore **one line per distinct blocked action, up to 100 lines per supervisor, and a summary of what the supervisor counted**, rather than literally one line per blocked call. What the summary counts is exactly: every network refusal the guard made (exact, since the guard decides), and every filesystem call the mirror judged refused (a prediction, which a race can make wrong, A.5.7), from the moment the supervisor armed until it ends (the guard: when no supervised task is left; the report-only supervisor: when its direct child has ended). Not counted: the report-only supervisor's drainer period after that (A.5.6), anything in A.10, and the timeout and resource lines, which each layer prints once on its own. A program that hammers one refused path in a loop would otherwise drown its own output and the grading log; the request asked for de-duplication or rate limiting for exactly that reason.

- **De-duplication.** A line is printed the first time its verb, noun and object (the judged path or endpoint) come together; every later occurrence is counted and not printed. The key is a 64-bit FNV-1a hash in a table of 4096 entries; a hash collision hides a distinct line (it errs towards a missing line, never a wrong one), and a full table stops recording new keys, so later distinct lines are still printed but no longer de-duplicated, up to the cap.
- **Cap.** At most 100 distinct lines per supervisor and run (`PHB_REPORT_LINES_MAXIMUM`). The 101st distinct denial prints one line, `Phobos: further blocked actions are counted but not shown.`, and nothing more.
- **Summary.** When the supervisor ends and anything was blocked, it prints the line the filesystem layer prints today, `Sandbox denials: network=N, filesystem=M. (PHB-EDENY)`, now with exact counts of blocked calls, followed, when lines were withheld, by `Phobos showed S of these; R repeats and C actions beyond the limit were counted but not shown.`
- **Direction.** Within what the summary counts, it errs towards fewer lines, never towards fewer counted actions: every counted call is counted once, printed or not.

## A.8 The other layers

### A.8.1 Network refusals (the guard)

The guard knows its refusals exactly; it does not mirror anything. Not every `EACCES` it answers is a policy decision with an object, so each answer site is classified, and only the first group prints a line:

- **Reported (a policy refusal with a valid object):** a stream `connect` whose destination no `[connect]` rule allows (connect to the Endpoint); a datagram `connect`, `sendto`, `sendmsg` or `sendmmsg` whose destination no rule allows (send to the Endpoint); a datagram on a socket bound to no port where the policy grants no ephemeral UDP bind (send to the Endpoint, the destination being known); a `socket` of a refused family or type (open the Socket Type); a `connect` to a UNIX socket path (connect to the Socket File); a `listen` on a socket bound to no port without the port-0 grant (listen on the Port chosen by the kernel).
- **Not reported, `--debug` only as today (no valid object, or not a policy decision):** a send with `MSG_FASTOPEN` (the guard refuses the flag before it reads any destination, so there is no judged endpoint to name, and reading one only to print it would name an object the guard never decided on); an address that cannot be read out of the command or is malformed; a socket the guard does not hold or did not create (inherited, received, evicted); a send with ancillary data or with flags the guard cannot pass on (`EOPNOTSUPP`); errors of the onward connection (`ECONNREFUSED`, a timeout), which are the destination's answer, not Phobos's.

Each reported site gains one call to the shared reporter, printed always, de-duplicated and capped like the filesystem lines; the existing `log_verbose` lines stay for `--debug`, since they carry the internal reason. A unit case per site pins its group.

**The endpoint text is not formatted twice.** Markus decided that the plan of PR 162 (prune on the layers) extends the guard's verbose refusal to name the address and not only the port, and that it introduces the one function in `core/phobos-seccomp-networksystem/` that formats an endpoint (address and port, IPv4 and IPv6 bracketed, escaped). **That PR introduces the function and this plan reuses it**: the "the Endpoint ..." part of every network line is that function's output followed by ` over TCP` or ` over UDP`, and PR 3 here is based on the PR of PR 162's plan that introduces it (stacked on it if it has not merged when PR 3 starts). This plan defines no second formatter.

### A.8.2 Bind ports

The network layer's own enforcer (`--no-filesystem ... --close-bind --bind-tcp P ...`) is the arming call for the bind model. The guard traps `bind` (report only, `CONTINUE`), reads the address, and for an IPv4 or IPv6 address judges the port against the model: closed bind, the named ports, the port-0 grant, by transport. The transport comes from the guard's own socket table (it records every socket it lets the command create), so a `bind` on a socket the guard does not know prints nothing. A `bind` on a UNIX path is judged by the filesystem model as `MAKE_SOCK` when the task is in the filesystem domain. With `-nnr` there is no network ruleset and nothing about ports to report; the report-only supervisor judges only UNIX paths.

### A.8.3 Timeout

`phobos-timeoutsystem.sh` prints the line for the time limit immediately before its existing `Timed out after Ns. (PHB-ETIMEOUT)`, under exactly the condition that prints that line today.

### A.8.4 Resources

The filesystem layer is the one that receives the command's status in every combination. When the resource layer set a CPU limit and the status is 152 (128 plus `SIGXCPU`, 24 on x86_64 and aarch64), or set a file size limit and the status is 153 (`SIGXFSZ`, 25), it prints the matching line with the limit from `limits.conf`. It errs towards a wrong line for a command that ends with status 152 or 153 by itself, which a shell cannot tell apart from the signal. The process, open file and memory limits are not detectable without seeing the result of `fork`, `open` or `mmap` (A.10).

## A.9 The heuristic counter

`count_denials` and its process substitution are removed. The supervisor's summary (A.7) prints the same line with exact counts. Without a supervisor (`-nfr -nnr`) neither layer can block anything, so no summary is printed. The integration suite `tests/integration/denial_report.sh` is rewritten to the new contract. This is a visible change for anyone who parsed the old numbers, and it is named in the pull request (Q3).

## A.10 What is not reported, and why

| Not reported | Why |
| --- | --- |
| A call refused by a filter with `SECCOMP_RET_ERRNO`: a non-native ABI, `io_uring_*`, `setsid`, `setpgid`, Docker's refusals | `ERRNO` beats `USER_NOTIF`, the kernel never notifies. Moving them to the supervisor would make a refusal depend on a user-space process; libuv probes `io_uring` on every start and would print a line for every Node run. Q2. |
| `ioctl` on a device (`IOCTL_DEVICE`) | The busiest call of any terminal-aware program; a filter cannot tell a device descriptor apart, and Landlock decides from the rights recorded when the descriptor was opened. |
| `connect` or `sendmsg` to a UNIX socket path under `-nnr` (`RESOLVE_UNIX`, ABI 9) | Those calls belong to the guard's set and may never be trapped by a report filter; with the network layer on, the guard refuses the UNIX family itself and reports it. The CI and local kernels are ABI 7 and 8 and do not enforce `RESOLVE_UNIX` at all. |
| `io_uring` file operations under `-nnr` | They never pass through seccomp. |
| An `openat2` with resolve flags, an `O_TMPFILE` open, a call relative to a deleted or unreachable directory | The mirror cannot reproduce them faithfully, so they are excluded by construction (A.5.4). |
| An interpreter the kernel opens for `execve` (`#!` line, ELF interpreter) | A kernel-internal open, not a system call; the line for the `execve` itself is missing when only the interpreter was refused. |
| Process, open file and memory limits | `EAGAIN`, `EMFILE` and `ENOMEM` are results, which the supervisor never sees. |
| An inbound connection the `[accept]` filter refuses | The actor is an outside client, not the program; it does not fit "the program tried". HAProxy logs it. |
| A TLS host name the egress broker refuses | HAProxy closes the connection after the guard already allowed it; the broker's own log would have to carry the line. Q4. |
| A blocked action after the command's direct child has ended (`-nnr`) | The drainer continues silently (A.5.6). |

## A.11 Decisions and the alternatives rejected

| Decision | Rejected alternatives |
| --- | --- |
| seccomp user notification with `CONTINUE` and a mirror | ptrace on return (A.3); audit, fanotify, `LD_PRELOAD`, eBPF (A.3); the command's own stderr (A.2) |
| One supervisor per run: the guard when the network layer is on, a report-only supervisor from the filesystem layer otherwise | two stacked listeners (`EBUSY`, measured); one new top-level supervisor that also takes over the guard's job (a rewrite of the network layer for no gain); installing the filter in the enforcer after `landlock_restrict_self` (the listener cannot reach a supervisor outside: `sendmsg` is the guard's, `unshare` and `pidfd_getfd` are refused) |
| Arm on `landlock_restrict_self`, rules from the enforcer's own command line | a rules file the network layer writes (a second computation that can drift from what the enforcer enforced); arming by counting `execve`s |
| Membership by a marker filter and `Seccomp_filters` | parent-chain walk, a magic system call, `personality` flags (A.5.3) |
| Mirror by inode walk | path-string prefixes (wrong for bind mounts and hard links, which Landlock follows by inode) |
| Lines name the judged path, with the named one beside it | the named path only (not what a policy must grant) |
| Verbs carry their preposition | "connect the Endpoint" |
| De-duplicate plus a cap of 100 plus a summary | time-based rate limiting (drops the first occurrence of a new denial in a burst); no limit (a loop floods the log) |
| Retire `count_denials` | keep both (two contradicting counts on one log) |
| Resource lines from the status | trapping `clone`, `mmap` and `open` results (not possible without ptrace) |
| A reporter that cannot start reports so and the run goes on | refuse the run (a diagnostic would become an availability dependency) |
| Synchronous wake-up where available | always asynchronous (30 times slower on a file loop, measured) |

## A.12 Tests, both directions

Every behaviour is pinned in both directions, in the image where it needs Landlock:

- **The reporter changes no result.** Every probe operation's return value and errno through `phobos.sh` equals its result through the standalone filesystem layer with `--no-own-reporter` (Landlock alone), for granted and refused operations alike (`reporting.sh`, Task 2.5).
- **Granted, silent, working.** A granted read, write, create, delete, rename and exec each succeeds and produces no `Phobos Security Error` line, under all eight combinations of `-ntr`, `-nnr`, `-nrr`.
- **Refused, refused, one line.** Each refused action of A.6.4 is still refused with the same errno and produces exactly one correctly formatted line, under all eight combinations with the filesystem layer on and through the standalone filesystem layer, for every action row of Task 2.5.
- **`-nfr`.** The same refused action succeeds (Landlock is off) and produces no filesystem line.
- **No widening.** Under guard plus reporter, a disallowed `connect` is still refused and a disallowed `bind` still fails, with exactly the errno `network.sh` already pins (the network cases compare against that suite's expectation, not against a second guard build); a unit test asserts that every response on a report trap is `CONTINUE` with error and value 0; a unit test asserts the report set and the guard's enforcement set are disjoint and that the report set contains no call any filter refuses with `ERRNO`.
- **Membership.** The filesystem layer's own `tee` and `sleep` produce no line although they read paths the policy does not grant.
- **Supervisor gone.** Killing the report-only supervisor mid-run makes the command's next refused and next granted `open` both fail with `ENOSYS`; neither succeeds where it should not.
- **Volume.** 100 000 refused opens of one file print one line and a summary that counts 100 000; 150 distinct refused files print 100 lines, the overflow notice, and a summary that counts 150.
- **Output safety.** A file name with a newline, an escape byte and a byte above 0x7f is quoted; the quoting matches bash `${v@Q}` under `LC_ALL=C` for a corpus of names.
- **Races.** A thread flipping a path buffer between a granted and a refused name never opens the refused file, and every line it causes names one of the two.

## A.13 Risks

| Risk | Mitigation |
| --- | --- |
| The guard does more work, and a reporter bug can take the guard down (fail closed, `ENOSYS`) | the reporter is a separate module with its own unit suite under the guard's 100 % line gate; no allocation per notification; defensive bounds on every read |
| Latency for network calls queued behind file notifications in the single-threaded guard | measured per notification at 2.3 µs plus 7 µs for the mirror; a connect waits for at most the notifications already queued |
| Mirror divergence from Landlock in an edge case | the cases the mirror cannot reproduce (`openat2` resolve flags, `O_TMPFILE`, deleted or unreachable directories) are excluded by construction and stay silent (A.5.4); every other row of A.6.4 is pinned against the kernel in both directions, and any divergence left only makes a line wrong or missing |
| A kernel without synchronous wake-up (before 6.6) | 30 times slower on file loops, 19 % on `javac`; reported once as a notice |
| JVM noise (A.4.3) | de-duplication bounds it; Q1 decides whether to quiet it |

## A.14 Open questions for Markus

Every other decision is taken in A.11; these four need you.

- **Q1. The JVM's tolerated refusals.** Under the shipped Java policy every Java run will print about 17 true lines about `/proc`, `/sys` and `/dev/tty` that the JVM survives. Options: (a) print them (truthful, noisy for students); (b) a `[quiet]` section in the base configuration that keeps them counted but not shown (needs the parser to learn a section); (c) grant read on exactly those `/proc` and `/sys` files in the Java base (a widening: "this now permits reading /proc/meminfo, ..., which it did not permit before"). The plan implements (a) and leaves (b) or (c) to your choice.
- **Q2. Filter-level refusals.** Should `io_uring`, `setsid` and `setpgid` refusals be reported? It would mean answering them from the supervisor instead of the filter, which keeps them refused even if the supervisor dies (`ENOSYS`), but makes Node print a line on every start.
- **Q3. The summary line.** Keeping `Sandbox denials: network=N, filesystem=M. (PHB-EDENY)` with exact counts changes what the numbers mean for anyone who parsed them. Keep the line, or rename it?
- **Q4. The egress broker.** Should HAProxy's refusal of a TLS host name print a line in the same format (a custom HAProxy log format on the deny path)? It is a separate change to `phobos-haproxy.sh` and is not planned here.

## A.15 Review record

The plan went through an independent read-only review in eight rounds before the pull request was opened; the findings and how each was resolved are recorded in Part C.

---

# Part B: Pull requests and tasks

The work lands as four pull requests, each green on its own, each based on the previous one, and PR 3 additionally on the PR of PR 162's plan that introduces the guard's endpoint formatter (A.8.1) (a stack, so each needs `workflow_dispatch` runs of `build.yml`, `lint.yml`, `test.yml` and `codeql.yml` linked in its body, AGENTS.md). Run every Linux suite in the run-phase image or the local `phobos-test-runner` image; the Mac has no Landlock. Build the run-phase image with:

```bash
CTX="$(mktemp -d)"
.github/scripts/assemble-run-phase-context.sh "$CTX"
docker build -f docker/run_phase/java/Dockerfile -t phobos-run-phase:local "$CTX"
```

## PR 1: The shared model and the message module (no behaviour change)

### Task 1.1: A non-exiting policy model in the Landlock enforcer

**Files:**
- Modify: `core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-options.c` and `-options.h`
- Modify: `core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-ruleset.c` and `-ruleset.h`
- Create: `core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-policy.c` and `-policy.h` (the diagnostics-free part: `parse_arguments_checked`, `remember_path_rule_checked`, `parse_number_checked`, `filesystem_rights_for_version`, `handled_network_access`, `close_bind_access`, `query_landlock_version`)
- Create: `core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-model.c` and `-model.h`
- Test: `tests/unit/phobos-landlock-filesystem-and-networksystem/landlock_filesystem_and_networksystem_unit.c`, `tests/unit/phobos-landlock-filesystem-and-networksystem/run.sh`

**Why a diagnostics-free module.** The supervisors link the model, and the guard already defines `log_verbose` in its own diagnostics module, as does the enforcer; linking the enforcer's `-diagnostics.c` into the guard would collide, and linking its exiting helpers into a supervisor would let a parse error end the supervisor (and turn every trapped call into `ENOSYS`). So the model and everything it calls live in `-policy.c`, `-path-rule.c` and `-model.c`, none of which calls a diagnostics function; `-options.c` and `-ruleset.c` keep the exiting wrappers the enforcer uses. A link test proves it: `seccomp_filesystem_run.sh` links the three files with no diagnostics source and must succeed.

**Interfaces:**
- Produces:

```c
/* Reads the command line into options, or answers false with the reason in error. Never exits. */
bool parse_arguments_checked(int argument_count, char *arguments[], struct options *options,
                             char *error, size_t error_size);

/* The kernel's Landlock version, or 0 when it has none. Never exits. */
int query_landlock_version(void);

struct model_rule {
    dev_t device;
    ino_t inode;
    uint64_t rights;
};

struct policy_model {
    struct model_rule rules[MAXIMUM_PATH_RULES];
    size_t rule_count;
    uint64_t handled_filesystem;
    uint64_t handled_network;
    struct options options;
};

/* Builds the model of the ruleset the enforcer builds from these arguments at this version:
 * every rule's inode and rights, exactly as add_path_rule computes them, and the handled rights.
 * Answers false with the reason in error when the arguments do not parse or a rule path cannot
 * be opened. Never exits. */
bool build_policy_model(int argument_count, char *arguments[], int landlock_version,
                        struct policy_model *model, char *error, size_t error_size);

/* The union of the rights every rule along the ancestors of an absolute, resolved path grants. */
uint64_t model_rights_along(const struct policy_model *model, const char *resolved_path);

/* Whether a bind to this port and transport passes the network ruleset this model describes. */
bool model_bind_permitted(const struct policy_model *model, bool datagram, uint16_t port);
```

- [ ] **Step 1: Write the failing tests**

Add to the unit file, beside the existing cases, and call them from `main`:

```c
static void test_parse_arguments_checked_refuses_without_exiting(void) {
    struct options options;
    char error[256];
    char *bad[] = {"enforcer", "--rights=rz", "/usr", "--", "/bin/true", NULL};
    memset(&options, 0, sizeof(options));
    CHECK(!parse_arguments_checked(5, bad, &options, error, sizeof(error)));
    CHECK(strstr(error, "'z' is not a right") != NULL);
}

static void test_model_unions_rights_along_the_path(void) {
    struct policy_model model;
    char error[256];
    char *arguments[] = {"enforcer", "--rights=rx", "/usr", "--rights=rw", "/tmp", "--",
                         "/bin/true", NULL};
    CHECK(build_policy_model(7, arguments, 8, &model, error, sizeof(error)));
    uint64_t usr = model_rights_along(&model, "/usr/bin/env");
    CHECK((usr & LANDLOCK_ACCESS_FILESYSTEM_EXECUTE) != 0);
    CHECK((usr & LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE) == 0);
    CHECK(model_rights_along(&model, "/etc/hostname") == 0);
    CHECK((model.handled_filesystem & LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE) != 0);
}

static void test_model_strips_directory_rights_from_a_file_rule(void) {
    struct policy_model model;
    char error[256];
    char *arguments[] = {"enforcer", "--rights=rwmd", "/etc/hostname", "--", "/bin/true", NULL};
    CHECK(build_policy_model(5, arguments, 8, &model, error, sizeof(error)));
    CHECK((model.rules[0].rights & DIRECTORY_ONLY_ACCESS_RIGHTS) == 0);
}

static void test_model_bind_follows_close_bind_and_port_rules(void) {
    struct policy_model model;
    char error[256];
    char *arguments[] = {"enforcer", "--no-filesystem", "--close-bind", "--bind-tcp", "8080",
                         "--ephemeral-bind-udp", "--", "/bin/true", NULL};
    CHECK(build_policy_model(8, arguments, 10, &model, error, sizeof(error)));
    CHECK(model_bind_permitted(&model, false, 8080));
    CHECK(!model_bind_permitted(&model, false, 8081));
    CHECK(model_bind_permitted(&model, true, 0));
    CHECK(!model_bind_permitted(&model, true, 53));
}
```

- [ ] **Step 2: Run the suite in the test runner and see the four new cases fail to link**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/unit/phobos-landlock-filesystem-and-networksystem/run.sh`
Expected: link errors for `parse_arguments_checked`, `build_policy_model`, `model_rights_along`, `model_bind_permitted`.

- [ ] **Step 3: Implement**

Move the parse path from `-options.c` into `-policy.c` as `parse_arguments_checked`, turning every `exit_with_format`/`exit_with_message`/`print_usage_and_exit` in it into a `snprintf(error, error_size, ...)` and `return false` (an empty `error` meaning "print the usage"); move `filesystem_rights_for_version`, `handled_network_access` and `close_bind_access` there unchanged. Keep `parse_arguments` in `-options.c` as the exiting wrapper the enforcer uses:

```c
void parse_arguments(int argument_count, char *arguments[], struct options *options) {
    char error[512];
    if (!parse_arguments_checked(argument_count, arguments, options, error, sizeof(error))) {
        if (error[0] == '\0') {
            print_usage_and_exit();
        }
        exit_with_message(error);
    }
}
```

Move the version query out of `detect_landlock_version` (in `-ruleset.c`) into `query_landlock_version` in `-policy.c` and call it from there. In `-model.c`, build the rules with the same helpers `add_path_rule` uses:

```c
static bool remember_model_rule(struct policy_model *model, const struct path_rule *rule,
                                int landlock_version, char *error, size_t error_size) {
    int descriptor = open(rule->path, open_flags_for_rule(rule));
    if (descriptor < 0) {
        snprintf(error, error_size, "cannot open %s: %s", rule->path, strerror(errno));
        return false;
    }
    struct stat status;
    bool stated = fstat(descriptor, &status) == 0;
    close(descriptor);
    if (!stated) {
        snprintf(error, error_size, "cannot stat %s: %s", rule->path, strerror(errno));
        return false;
    }
    uint64_t rights = rights_granted_for(rule, landlock_version);
    if (!S_ISDIR(status.st_mode)) {
        rights &= ~DIRECTORY_ONLY_ACCESS_RIGHTS;
    }
    struct model_rule *slot = &model->rules[model->rule_count];
    slot->device = status.st_dev;
    slot->inode = status.st_ino;
    slot->rights = rights;
    model->rule_count++;
    return true;
}

uint64_t model_rights_along(const struct policy_model *model, const char *resolved_path) {
    char walk[PATH_MAX];
    uint64_t granted = 0;
    if (snprintf(walk, sizeof(walk), "%s", resolved_path) >= (int)sizeof(walk)) {
        return 0;
    }
    for (;;) {
        struct stat status;
        if (stat(walk, &status) == 0) {
            for (size_t index = 0; index < model->rule_count; index++) {
                if (model->rules[index].device == status.st_dev
                    && model->rules[index].inode == status.st_ino) {
                    granted |= model->rules[index].rights;
                }
            }
        }
        char *slash = strrchr(walk, '/');
        if (slash == NULL || strcmp(walk, "/") == 0) {
            return granted;
        }
        if (slash == walk) {
            walk[1] = '\0';
        } else {
            *slash = '\0';
        }
    }
}
```

`build_policy_model` calls `parse_arguments_checked`, sets `handled_filesystem` to 0 for `--no-filesystem` and to `filesystem_rights_for_version(landlock_version)` otherwise, sets `handled_network` with `handled_network_access(&options) | close_bind_access(&options, landlock_version)`, and remembers every rule. `model_bind_permitted` answers true when the direction is not handled, true for a named port, true for port 0 when the ephemeral grant for that transport is set, and false otherwise. Add both modules to the `MODULES` of `run.sh`; the enforcer's `gcc-14` line in `docker/run_phase/java/Dockerfile` compiles them through its existing `phobos-landlock-filesystem-and-networksystem*.c` glob, so the Dockerfile needs no change in this task.

- [ ] **Step 4: Run the suite and see it pass, with the enforcer's existing cases unchanged**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/unit/phobos-landlock-filesystem-and-networksystem/run.sh`
Expected: every case passes; the existing refusal cases still exit with 125.

- [ ] **Step 5: Lint and commit**

```bash
gcc-14 -std=gnu23 -fsyntax-only -Wall -Wextra -Werror -fanalyzer core/phobos-landlock-filesystem-and-networksystem/*.c
cppcheck --std=c23 --enable=warning --quiet --error-exitcode=1 core/phobos-landlock-filesystem-and-networksystem/*.c
git add core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-options.c \
  core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-options.h \
  core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-ruleset.c \
  core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-ruleset.h \
  core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-policy.c \
  core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-policy.h \
  core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-model.c \
  core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-model.h \
  tests/unit/phobos-landlock-filesystem-and-networksystem/landlock_filesystem_and_networksystem_unit.c \
  tests/unit/phobos-landlock-filesystem-and-networksystem/run.sh
git commit -m "Give the Landlock enforcer a policy model that answers without exiting"
```

### Task 1.2: The message module

**Files:**
- Create: `core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-message.c` and `-message.h`
- Create: `tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_unit.c`, `tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh`
- Modify: `.github/workflows/build.yml` (run the new suite in the `unit` job), `.github/scripts/assemble-run-phase-context.sh` (copy `core/phobos-seccomp-filesystem/*.c` and `*.h`)

**Interfaces:**
- Produces:

```c
enum report_layer {
    REPORT_LAYER_FILESYSTEM,
    REPORT_LAYER_NETWORK,
};

/* Prints "Phobos Security Error: the program tried to illegally <verb> the <noun> <object>
 * <detail> but was blocked by Phobos." the first time verb, noun and object come together, counts
 * every call, and respects the cap. object_is_path quotes object (and detail_path, when not NULL,
 * as " (named as ...)") the bash ${v@Q} way; otherwise object is printed as it is. */
void report_blocked(enum report_layer layer, const char *verb, const char *noun,
                    const char *object, bool object_is_path, const char *detail_path);

/* Prints "Sandbox denials: network=N, filesystem=M. (PHB-EDENY)" and, when lines were withheld,
 * the line saying how many, when anything was blocked. */
void report_summary(void);

/* Writes value quoted like bash ${value@Q} under LC_ALL=C into out, cutting value at 1024 bytes
 * and appending " (truncated)" outside the quotes. Exposed for the tests. */
void quote_like_bash(const char *value, char *out, size_t size);

static constexpr size_t REPORT_LINES_MAXIMUM = 100;
static constexpr size_t REPORT_KEYS_MAXIMUM = 4096;
static constexpr size_t REPORT_PATH_SHOWN_MAXIMUM = 1024;
```

- [ ] **Step 1: Write the failing tests**

```c
static void test_quoting_matches_bash(void) {
    char out[8192];
    quote_like_bash("/etc/hostname", out, sizeof(out));
    CHECK(strcmp(out, "'/etc/hostname'") == 0);
    quote_like_bash("/tmp/odd\nname", out, sizeof(out));
    CHECK(strcmp(out, "$'/tmp/odd\\nname'") == 0);
    quote_like_bash("/tmp/it's", out, sizeof(out));
    CHECK(strcmp(out, "'/tmp/it'\\''s'") == 0);
    quote_like_bash("/tmp/q'and\nnl", out, sizeof(out));
    CHECK(strcmp(out, "$'/tmp/q\\'and\\nnl'") == 0);
    quote_like_bash("/tmp/back\\slash", out, sizeof(out));
    CHECK(strcmp(out, "'/tmp/back\\slash'") == 0);
    quote_like_bash("/tmp/\x1b[31m", out, sizeof(out));
    CHECK(strcmp(out, "$'/tmp/\\E[31m'") == 0);
    quote_like_bash("/tmp/\xc3\xa9", out, sizeof(out));
    CHECK(strcmp(out, "$'/tmp/\\303\\251'") == 0);
    quote_like_bash("/tmp/del\x7f", out, sizeof(out));
    CHECK(strcmp(out, "$'/tmp/del\\177'") == 0);
    quote_like_bash("", out, sizeof(out));
    CHECK(strcmp(out, "''") == 0);
}

static void test_a_line_is_byte_exact(void) {
    reset_report_for_tests();
    capture_stderr_begin();
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/etc/shadow", true, NULL);
    const char *line = capture_stderr_end();
    CHECK(strcmp(line, "Phobos Security Error: the program tried to illegally read the File "
                       "'/etc/shadow' but was blocked by Phobos.\n") == 0);
}

static void test_repeats_are_counted_not_printed(void) {
    reset_report_for_tests();
    capture_stderr_begin();
    for (int round = 0; round < 1000; round++) {
        report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/etc/shadow", true, NULL);
    }
    report_summary();
    const char *text = capture_stderr_end();
    CHECK(count_occurrences(text, "Phobos Security Error") == 1);
    CHECK(strstr(text, "Sandbox denials: network=0, filesystem=1000. (PHB-EDENY)") != NULL);
    CHECK(strstr(text, "Phobos showed 1 of these; 999 repeats and 0 actions beyond the limit") != NULL);
}

static void test_the_cap_holds(void) {
    reset_report_for_tests();
    capture_stderr_begin();
    char path[64];
    for (int index = 0; index < 150; index++) {
        snprintf(path, sizeof(path), "/denied/%d", index);
        report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", path, true, NULL);
    }
    report_summary();
    const char *text = capture_stderr_end();
    CHECK(count_occurrences(text, "Phobos Security Error") == 100);
    CHECK(count_occurrences(text, "Phobos: further blocked actions are counted but not shown.") == 1);
    CHECK(strstr(text, "filesystem=150") != NULL);
}

static void test_named_path_and_truncation(void) {
    char longpath[2048];
    memset(longpath, 'a', sizeof(longpath) - 1);
    longpath[0] = '/';
    longpath[sizeof(longpath) - 1] = '\0';
    reset_report_for_tests();
    capture_stderr_begin();
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", "/etc/locale.alias", true,
                   "/usr/share/locale/locale.alias");
    report_blocked(REPORT_LAYER_FILESYSTEM, "read", "File", longpath, true, NULL);
    const char *text = capture_stderr_end();
    CHECK(strstr(text, "'/etc/locale.alias' (named as '/usr/share/locale/locale.alias') but") != NULL);
    CHECK(strstr(text, "' (truncated) but was blocked by Phobos.") != NULL);
}
```

`seccomp_filesystem_run.sh` follows `tests/unit/phobos-seccomp-networksystem/seccomp_networksystem_run.sh`: it builds the modules with `-DPHOBOS_REPORTER_UNIT_TEST` (which exposes `reset_report_for_tests`), redirects `stderr` through a pipe for `capture_stderr_begin`/`capture_stderr_end`, supports `--coverage` and gates lines at 100 %. It also runs a corpus check against bash itself:

```bash
# The quoting must be bash's own, so a corpus of names is quoted by both and compared.
while IFS= read -r -d '' name; do
  expected="$(LC_ALL=C bash -c 'printf "%s" "${1@Q}"' _ "$name")"
  actual="$("$WORK/quote-probe" "$name")"
  [[ "$expected" == "$actual" ]] || { echo "quoting differs for ${expected}: ${actual}" >&2; exit 1; }
done < <(printf '%s\0' '/plain' "/it's" $'/new\nline' $'/tab\there' $'/esc\e[31m' $'/\xc3\xa9' \
  '/back\slash' '/sp ace' $'/cr\r' $'/bell\a' $'/del\x7f' $'/q\'and\nnl' $'/b\\s\nx' $'/vt\v\f\b')
```

The empty name cannot pass through a NUL-separated list and is covered by the C case above. This corpus is the one the spike was checked against (A.6.1).

- [ ] **Step 2: Run and see it fail**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh`
Expected: link errors for `report_blocked`, `report_summary`, `quote_like_bash`.

- [ ] **Step 3: Implement**

```c
static const char PREFIX[] = "Phobos Security Error: the program tried to illegally ";
static const char SUFFIX[] = " but was blocked by Phobos.";
static uint64_t seen_keys[REPORT_KEYS_MAXIMUM];
static size_t seen_count = 0;
static size_t lines_shown = 0;
static unsigned long blocked_network = 0;
static unsigned long blocked_filesystem = 0;
static unsigned long withheld_repeats = 0;
static unsigned long withheld_beyond_limit = 0;
static bool overflow_said = false;

/* The ANSI-C escape bash writes for one byte inside $'...', or NULL for a byte it writes in octal
 * or as it is. */
static const char *ansi_c_escape(unsigned char byte) {
    switch (byte) {
    case '\'':
        return "\\'";
    case '\\':
        return "\\\\";
    case '\a':
        return "\\a";
    case '\b':
        return "\\b";
    case '\t':
        return "\\t";
    case '\n':
        return "\\n";
    case '\v':
        return "\\v";
    case '\f':
        return "\\f";
    case '\r':
        return "\\r";
    case 0x1b:
        return "\\E";
    default:
        return NULL;
    }
}

void quote_like_bash(const char *value, char *out, size_t size) {
    size_t length = strnlen(value, REPORT_PATH_SHOWN_MAXIMUM);
    bool truncated = value[length] != '\0';
    bool plain = true;
    for (size_t index = 0; index < length; index++) {
        unsigned char byte = (unsigned char)value[index];
        if (byte < 0x20 || byte > 0x7e) {
            plain = false;
        }
    }
    size_t used = (size_t)snprintf(out, size, plain ? "'" : "$'");
    for (size_t index = 0; index < length && used + 8 < size; index++) {
        unsigned char byte = (unsigned char)value[index];
        const char *escape = NULL;
        if (plain && byte == '\'') {
            escape = "'\\''";
        } else if (!plain) {
            escape = ansi_c_escape(byte);
        }
        if (escape != NULL) {
            used += (size_t)snprintf(out + used, size - used, "%s", escape);
        } else if (!plain && (byte < 0x20 || byte > 0x7e)) {
            used += (size_t)snprintf(out + used, size - used, "\\%03o", byte);
        } else {
            out[used] = (char)byte;
            used++;
            out[used] = '\0';
        }
    }
    used += (size_t)snprintf(out + used, size - used, "'");
    if (truncated && used < size) {
        snprintf(out + used, size - used, " (truncated)");
    }
}
```

This is the spike's `quote` (checked against bash 5.2.21 in the run-phase image) plus the cut. `report_blocked` increments the layer's counter, computes the FNV-1a key of verb, noun and object (each followed by a 0xff separator byte), returns after counting a repeat, and otherwise prints `PREFIX`, the verb, ` the `, the noun, a space, the object (quoted when `object_is_path`), ` (named as <quoted detail>)` when `detail_path` is not NULL, and `SUFFIX` with one `fprintf` and a newline, unless `lines_shown == REPORT_LINES_MAXIMUM`, where it counts `withheld_beyond_limit` and prints the overflow notice once. Should a later bash quote differently, the corpus check in `seccomp_filesystem_run.sh` fails and the C follows bash.

- [ ] **Step 4: Run and see it pass at 100 % lines**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh --coverage`
Expected: every case passes, the corpus agrees with bash, coverage 100 % of lines.

- [ ] **Step 5: Lint and commit**

```bash
shellcheck -x -S warning tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh
git add core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-message.c \
  core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-message.h \
  tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_unit.c \
  tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh \
  .github/workflows/build.yml .github/scripts/assemble-run-phase-context.sh
git commit -m "Add the module that words, quotes, de-duplicates and counts a blocked action"
```

## PR 2: The report-only supervisor, and `-nnr` runs report filesystem denials

### Task 2.1: Decode a trapped call into what Landlock checks

**Files:**
- Create: `core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-access.c` and `-access.h`
- Test: `tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_unit.c`

**Interfaces:**
- Produces:

```c
struct named_object {
    int directory;          /* AT_FDCWD or the descriptor the name is relative to */
    uint64_t name_address;  /* the pointer to the name in the command's memory */
};

struct access_request {
    size_t object_count;              /* 1, or 2 for rename and link */
    struct named_object objects[2];
    int open_flags;                   /* openat, openat2, open, creat */
    unsigned int mode;                /* mknodat, mknod */
    unsigned int rename_flags;        /* renameat2 */
    int unlink_flags;                 /* unlinkat */
    bool arming;                      /* landlock_restrict_self */
    bool socket_bind;                 /* bind: object 0 is the sockaddr */
    uint32_t socket_address_length;
};

/* Fills request from the trapped call's number and scalar arguments. Answers false for a call the
 * reporter does not decode, which is then continued silently. openat2's flags are behind a
 * pointer, so its how pointer is put into name_address of object 1 for the caller to read. */
bool decode_trapped_call(const struct seccomp_data *data, struct access_request *request);

/* The trap list both filters append, in one place, and its length. */
extern const int REPORT_TRAPPED_CALLS[];
extern const size_t REPORT_TRAPPED_CALL_COUNT;
```

- [ ] **Step 1: Write the failing tests**

```c
static void test_decode_openat(void) {
    struct seccomp_data data = {.nr = __NR_openat, .arch = GUARD_NATIVE_AUDIT_ARCH,
                                .args = {(uint64_t)AT_FDCWD, 0x1000, O_WRONLY | O_CREAT, 0644}};
    struct access_request request;
    CHECK(decode_trapped_call(&data, &request));
    CHECK(request.object_count == 1);
    CHECK(request.objects[0].directory == AT_FDCWD);
    CHECK(request.objects[0].name_address == 0x1000);
    CHECK(request.open_flags == (O_WRONLY | O_CREAT));
}

static void test_decode_renameat2_has_two_objects(void) {
    struct seccomp_data data = {.nr = __NR_renameat2, .args = {3, 0x1000, 4, 0x2000, RENAME_NOREPLACE}};
    struct access_request request;
    CHECK(decode_trapped_call(&data, &request));
    CHECK(request.object_count == 2);
    CHECK(request.objects[1].directory == 4);
    CHECK(request.rename_flags == RENAME_NOREPLACE);
}

static void test_decode_restrict_self_arms(void) {
    struct seccomp_data data = {.nr = SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF};
    struct access_request request;
    CHECK(decode_trapped_call(&data, &request));
    CHECK(request.arming);
}

static void test_report_set_never_names_a_guard_call(void) {
    const int guard_enforced[] = {__NR_socket, __NR_connect, __NR_listen, __NR_sendto,
                                  __NR_sendmsg, __NR_sendmmsg, __NR_io_uring_setup,
                                  __NR_io_uring_enter, __NR_io_uring_register, __NR_setsid,
                                  __NR_setpgid};
    for (size_t index = 0; index < REPORT_TRAPPED_CALL_COUNT; index++) {
        for (size_t guard = 0; guard < sizeof(guard_enforced) / sizeof(guard_enforced[0]); guard++) {
            CHECK(REPORT_TRAPPED_CALLS[index] != guard_enforced[guard]);
        }
    }
}
```

Add one case per row of A.6.4, including the legacy x86_64 calls under `#ifdef __NR_open`, and one for an undecoded number answering false.

- [ ] **Step 2: Run and see them fail**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh`
Expected: link errors for `decode_trapped_call` and `REPORT_TRAPPED_CALLS`.

- [ ] **Step 3: Implement**

```c
const int REPORT_TRAPPED_CALLS[] = {
#ifdef __NR_open
    __NR_open, __NR_creat, __NR_mkdir, __NR_rmdir, __NR_unlink, __NR_rename, __NR_link,
    __NR_symlink, __NR_mknod,
#endif
    __NR_openat, __NR_openat2, __NR_execve, __NR_execveat, __NR_mkdirat, __NR_mknodat,
    __NR_unlinkat, __NR_renameat, __NR_renameat2, __NR_linkat, __NR_symlinkat, __NR_truncate,
    __NR_bind, SYSCALL_NUMBER_LANDLOCK_RESTRICT_SELF,
};
const size_t REPORT_TRAPPED_CALL_COUNT = sizeof(REPORT_TRAPPED_CALLS) / sizeof(REPORT_TRAPPED_CALLS[0]);
```

`decode_trapped_call` is one `switch` over `data->nr` filling the fields from `data->args` as the kernel numbers them (`openat(dirfd, name, flags, mode)`, `renameat2(olddirfd, old, newdirfd, new, flags)`, `linkat(olddirfd, old, newdirfd, new, flags)`, `symlinkat(target, newdirfd, linkpath)` where only `linkpath` is an object, `execveat(dirfd, name, argv, envp, flags)`, `bind(fd, address, length)`); the legacy calls use `AT_FDCWD`. In the real file the array lists one name per line.

- [ ] **Step 4: Run and see them pass**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh --coverage`
Expected: pass, 100 % lines.

- [ ] **Step 5: Commit**

```bash
git add core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-access.c \
  core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-access.h \
  tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_unit.c
git commit -m "Decode each trapped path call into the objects Landlock judges"
```

### Task 2.2: Read, resolve and judge, then report

**Files:**
- Create: `core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-path.c` and `-path.h`
- Create: `core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-judge.c` and `-judge.h`
- Test: `tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_unit.c`

**Interfaces:**
- Consumes: `struct access_request` (Task 2.1), `struct policy_model`, `model_rights_along` (Task 1.1), `report_blocked` (Task 1.2).
- Produces:

```c
/* Reads a NUL-terminated name of at most PATH_MAX bytes out of the command, page by page, and
 * makes it absolute against /proc/<pid>/cwd or /proc/<pid>/fd/<directory>. */
bool read_absolute_name(pid_t pid, const struct named_object *object, char *out, size_t size);

/* Resolves a name the way Landlock sees it. anchor receives the path whose ancestors are walked:
 * the object itself (parent == false), or its resolved parent directory (parent == true). shown
 * receives the path the line names: the resolved object, or the resolved parent joined with the
 * last name as the program gave it. The two differ only for a call that creates or removes a name. */
bool resolve_for_landlock(const char *absolute, bool parent, char *anchor, size_t anchor_size,
                          char *shown, size_t shown_size);

/* Judges one decoded request against the filesystem model and reports it when Landlock refuses
 * it. Reads only; never answers the notification. Returns after at most one report_blocked. */
void judge_and_report(pid_t pid, const struct access_request *request,
                      const struct policy_model *filesystem);
```

- [ ] **Step 1: Write the failing tests**

The unit suite interposes `process_vm_readv`, `readlink`, `stat`, `lstat` and `realpath` through the linker the way the guard's suite does (`-Wl,--wrap=`), so each case states the command's memory, its working directory and the filesystem it sees:

```c
static void test_relative_create_under_a_denied_parent(void) {
    fake_memory_string(0x1000, "out/report.txt");
    fake_readlink("/proc/42/cwd", "/var/tmp/testing-dir");
    fake_directory("/var/tmp/testing-dir/out");
    fake_absent("/var/tmp/testing-dir/out/report.txt");
    struct policy_model model = model_with_rule("/var/tmp/testing-dir", "rx");
    struct access_request request = {.object_count = 1, .objects = {{AT_FDCWD, 0x1000}},
                                     .open_flags = O_WRONLY | O_CREAT};
    capture_stderr_begin();
    judge_and_report(42, &request, &model);
    CHECK(strcmp(capture_stderr_end(), "Phobos Security Error: the program tried to illegally "
                 "create the File '/var/tmp/testing-dir/out/report.txt' but was blocked by "
                 "Phobos.\n") == 0);
}

static void test_granted_read_is_silent(void) {
    fake_memory_string(0x1000, "/usr/lib/os-release");
    fake_file("/usr/lib/os-release");
    struct policy_model model = model_with_rule("/usr", "rx");
    struct access_request request = {.object_count = 1, .objects = {{AT_FDCWD, 0x1000}},
                                     .open_flags = O_RDONLY};
    capture_stderr_begin();
    judge_and_report(42, &request, &model);
    CHECK(strcmp(capture_stderr_end(), "") == 0);
}

static void test_missing_name_without_create_is_silent(void) {
    fake_memory_string(0x1000, "/etc/nothing-here");
    fake_absent("/etc/nothing-here");
    struct policy_model model = model_with_rule("/usr", "rx");
    struct access_request request = {.object_count = 1, .objects = {{AT_FDCWD, 0x1000}},
                                     .open_flags = O_RDONLY};
    capture_stderr_begin();
    judge_and_report(42, &request, &model);
    CHECK(strcmp(capture_stderr_end(), "") == 0);
}
```

Add one case per row of A.6.4 and per rule of A.6.3 (rename order, create-then-write, execute with only `READ_FILE` missing, `O_PATH` silent, `O_TRUNC` as write, `RENAME_EXCHANGE`, the named-as detail for a symbolic link, an unreadable name and a vanished notification both silent), and one per exclusion of A.5.4, each silent although the model refuses: an `openat2` with `RESOLVE_BENEATH`, an `O_TMPFILE` open, a relative name under a working directory that reads back with ` (deleted)`, and one whose directory descriptor reads back as `(unreachable)`. Then one case per row of the whitelist's "silent with" column (`execveat` with `AT_EMPTY_PATH`, `linkat` with `AT_SYMLINK_FOLLOW` and with `AT_EMPTY_PATH`, `RENAME_WHITEOUT`, an abstract UNIX `bind`, an unknown open flag), and one per pre-emption: `O_CREAT|O_EXCL`, `mkdirat`, `mknodat`, `symlinkat`, `linkat` and `RENAME_NOREPLACE` on an existing name, a file whose mode refuses the access (`faccessat` interposed to answer `EACCES`), a task whose `/proc/<pid>/status` shows a different `Uid` line than the supervisor's (silent, and `faccessat` never called), `O_DIRECTORY` on a file, `unlinkat` without `AT_REMOVEDIR` on a directory, `O_NOFOLLOW` and `execveat` with `AT_SYMLINK_NOFOLLOW` on a final symbolic link, and `O_NOATIME`, each silent although the model refuses.

- [ ] **Step 2: Run and see them fail**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh`
Expected: link errors for `read_absolute_name`, `resolve_for_landlock`, `judge_and_report`.

- [ ] **Step 3: Implement**

Port `read_child_string`, `absolute_path` and `resolve` from the spike (`docs/superpowers/plans/2026-10-05-denial-reporting-spike/denial-report-spike.c`) into `-path.c` unchanged in behaviour, with every `snprintf` checked for truncation. `judge_and_report` follows A.6.3 and A.6.4: compute the wanted rights and the object per row, skip when the name does not exist and is not created, resolve into `anchor` and `shown`, compare `wanted & model->handled_filesystem & ~model_rights_along(model, anchor)`, and call `report_blocked(REPORT_LAYER_FILESYSTEM, verb, noun, shown, true, strcmp(shown, absolute) != 0 ? absolute : NULL)` with the verb and noun from A.6.2. The line therefore always names the file or directory acted on, never the parent whose rights were checked (the spike already reports the object, `denial-report-spike.c`, `report(verb, noun, absolute)`). Add the unit cases for this: a refused `mkdir out/new` names `'<cwd>/out/new'`, not `'<cwd>/out'`; a refused `unlink` through a symbolic link to the parent names the resolved parent joined with the name and shows the named path as the detail; and the truncation case of A.5.4 at model versions 2 and 3. The verb and noun come from one table, so the wording lives in one place:

```c
struct right_wording {
    uint64_t right;
    const char *verb;
    const char *noun_for_file;
    const char *noun_for_directory;
};

static const struct right_wording WORDING[] = {
    {LANDLOCK_ACCESS_FILESYSTEM_WRITE_FILE, "write", "File", "File"},
    {LANDLOCK_ACCESS_FILESYSTEM_TRUNCATE, "write", "File", "File"},
    {LANDLOCK_ACCESS_FILESYSTEM_READ_FILE, "read", "File", "File"},
    {LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY, "read", "Directory", "Directory"},
    {LANDLOCK_ACCESS_FILESYSTEM_EXECUTE, "execute", "File", "File"},
    {LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE, "create", "File", "File"},
    {LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY, "create", "Directory", "Directory"},
    {LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET, "create", "Socket File", "Socket File"},
    {LANDLOCK_ACCESS_FILESYSTEM_MAKE_NAMED_PIPE, "create", "Named Pipe", "Named Pipe"},
    {LANDLOCK_ACCESS_FILESYSTEM_MAKE_SYMBOLIC_LINK, "create", "Symbolic Link", "Symbolic Link"},
    {LANDLOCK_ACCESS_FILESYSTEM_MAKE_CHARACTER_DEVICE, "create", "Device", "Device"},
    {LANDLOCK_ACCESS_FILESYSTEM_MAKE_BLOCK_DEVICE, "create", "Device", "Device"},
    {LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE, "delete", "File", "File"},
    {LANDLOCK_ACCESS_FILESYSTEM_REMOVE_DIRECTORY, "delete", "Directory", "Directory"},
};
```

`move` and `link` are worded in the rename and link branches, because their object is two paths: the object string is `'<from>' to '<to>'`, built from two `quote_like_bash` results and passed with `object_is_path` false.

- [ ] **Step 4: Run and see them pass at 100 % lines**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh --coverage`
Expected: pass, 100 % lines.

- [ ] **Step 5: Commit**

```bash
git add core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-path.c \
  core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-path.h \
  core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-judge.c \
  core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-judge.h \
  tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_unit.c
git commit -m "Judge a trapped path call against the Landlock model and report a refusal"
```

### Task 2.3: Arming, membership and the marker

**Files:**
- Create: `core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-reporter.c` and `-reporter.h`
- Modify: `core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem.c`, `-options.c`, `-options.h` (the `--mark-reported-domain` flag)
- Test: `tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_unit.c`, `tests/unit/phobos-landlock-filesystem-and-networksystem/landlock_filesystem_and_networksystem_unit.c`

**Interfaces:**
- Consumes: Tasks 1.1, 1.2, 2.1, 2.2.
- Produces:

```c
/* Tells the reporter the enforcer's path, which arming compares with /proc/<pid>/exe (A.5.3).
 * Both supervisors take it as --landlock-bin, from the same value the layers give the enforcer. */
void reporter_configure(const char *landlock_bin);

/* The arming state machine's state, for the tests and the --verbose lines. */
enum reporter_state {
    REPORTER_UNARMED,
    REPORTER_NETWORK_ARMED,
    REPORTER_FILESYSTEM_ARMED,
};
enum reporter_state reporter_current_state(void);

/* Whether this notification is one of the report traps (the filters share REPORT_TRAPPED_CALLS). */
bool reporter_handles(const struct seccomp_notif *request);

/* Services one report-trap notification: arms on landlock_restrict_self, judges a call of a task in
 * the filesystem domain, and always answers CONTINUE. Never answers anything else. */
void reporter_service(int notify_descriptor, const struct seccomp_notif *request,
                      struct seccomp_notif_resp *response);

/* Gives the reporter the guard's socket table, so a bind can be judged by its transport; the
 * report-only supervisor passes NULL and judges UNIX paths only. */
void reporter_use_socket_types(int (*socket_type_of)(pid_t pid, int descriptor));
```

- [ ] **Step 1: Write the failing tests**

```c
static void test_only_continue_is_ever_answered(void) {
    struct seccomp_notif request = notification(__NR_openat, 42, AT_FDCWD, 0x1000, O_RDONLY);
    struct seccomp_notif_resp response;
    fake_memory_string(0x1000, "/etc/shadow");
    arm_with_cmdline(42, "enforcer\0--rights=rx\0/usr\0--\0/bin/cat\0", 3);
    fake_filter_count(42, 4);
    reporter_service(7, &request, &response);
    CHECK(last_notify_response.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    CHECK(last_notify_response.error == 0);
    CHECK(last_notify_response.val == 0);
}

static void test_a_task_outside_the_domain_is_never_judged(void) {
    arm_with_cmdline(42, "enforcer\0--rights=rx\0/usr\0--\0/bin/cat\0", 3);
    fake_filter_count(43, 3);
    struct seccomp_notif request = notification(__NR_openat, 43, AT_FDCWD, 0x1000, O_RDONLY);
    struct seccomp_notif_resp response;
    fake_memory_string(0x1000, "/etc/shadow");
    capture_stderr_begin();
    reporter_service(7, &request, &response);
    CHECK(strcmp(capture_stderr_end(), "") == 0);
}

static void test_the_network_enforcer_arms_only_the_bind_model(void) {
    arm_with_cmdline(40, "enforcer\0--no-filesystem\0--close-bind\0--\0bash\0", 3);
    fake_filter_count(41, 4);
    struct seccomp_notif request = notification(__NR_openat, 41, AT_FDCWD, 0x1000, O_RDONLY);
    struct seccomp_notif_resp response;
    fake_memory_string(0x1000, "/etc/shadow");
    capture_stderr_begin();
    reporter_service(7, &request, &response);
    CHECK(strcmp(capture_stderr_end(), "") == 0);
}

static void test_both_enforcers_arm_in_order_and_nothing_rearms(void) {
    reporter_configure("/var/tmp/opt/core/phobos-landlock-filesystem-and-networksystem");
    fake_exe(40, "/var/tmp/opt/core/phobos-landlock-filesystem-and-networksystem");
    fake_exe(42, "/var/tmp/opt/core/phobos-landlock-filesystem-and-networksystem");
    fake_exe(50, "/var/tmp/testing-dir/copied-enforcer");
    arm_with_cmdline(40, "enforcer\0--no-filesystem\0--close-bind\0--\0bash\0", 3);
    CHECK(reporter_current_state() == REPORTER_NETWORK_ARMED);
    arm_with_cmdline(42, "enforcer\0--rights=rx\0/usr\0--\0/bin/cat\0", 3);
    CHECK(reporter_current_state() == REPORTER_FILESYSTEM_ARMED);
    arm_with_cmdline(50, "enforcer\0--rights=rwxmd\0/\0--\0/bin/cat\0", 5);
    CHECK(reporter_current_state() == REPORTER_FILESYSTEM_ARMED);
    CHECK(filesystem_model_rule_path_count() == 1);
}

static void test_a_caller_that_is_not_the_enforcer_never_arms(void) {
    reporter_configure("/var/tmp/opt/core/phobos-landlock-filesystem-and-networksystem");
    fake_exe(42, "/usr/bin/python3");
    arm_with_cmdline(42, "enforcer\0--rights=rx\0/usr\0--\0/bin/cat\0", 3);
    CHECK(reporter_current_state() == REPORTER_UNARMED);
}

static void test_a_rejected_cmdline_disarms_with_one_notice(void) {
    arm_with_cmdline(42, "enforcer\0--rights=zz\0/usr\0--\0/bin/cat\0", 3);
    CHECK(strstr(captured_stderr(), "Phobos: filesystem denial reporting is off for this run") != NULL);
}
```

In the enforcer's suite: with `--mark-reported-domain` the enforcer installs exactly one more filter after `landlock_restrict_self` (the wrapped `syscall` records `SYS_seccomp` with `SECCOMP_SET_MODE_FILTER`, flags 0, and a one-instruction `SECCOMP_RET_ALLOW` program after the restrict call), and without it none.

- [ ] **Step 2: Run both suites and see them fail**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash -c 'bash tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh; bash tests/unit/phobos-landlock-filesystem-and-networksystem/run.sh'`
Expected: link errors for the reporter; the enforcer refuses the unknown flag.

- [ ] **Step 3: Implement**

The reporter reads `/proc/<pid>/cmdline` into a buffer that grows to the whole argument area, splits it at NUL bytes into an `argv`, calls `build_policy_model` with `query_landlock_version()`, records `filter_count(pid)` (the spike's reader of `Seccomp_filters`), and keeps one filesystem model and one network model in static storage. Every read from the command is followed by `ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id)`; a vanished notification is not answered. The answer is always:

```c
static void answer_continue(int notify_descriptor, struct seccomp_notif_resp *response, __u64 id) {
    memset(response, 0, sizeof(*response));
    response->id = id;
    response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    if (ioctl(notify_descriptor, SECCOMP_IOCTL_NOTIF_SEND, response) != 0 && errno != ENOENT) {
        log_verbose("notify continue: %s", strerror(errno));
    }
}
```

In the enforcer, `--mark-reported-domain` sets `options.mark_reported_domain`; `main` calls `install_report_marker()` right after `apply_restriction` and before `exec_command`:

```c
/* Installs a filter that allows every call and has no listener, so the supervisor can tell the
 * tasks of this Landlock domain from the layer's helpers beside it by their filter count. It
 * changes no outcome: ALLOW is the weakest action and every other filter still decides. */
static void install_report_marker(void) {
    struct sock_filter allow_all[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = 1, .filter = allow_all};
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0) {
        exit_with_system_error("seccomp marker");
    }
}
```

- [ ] **Step 4: Run both suites and see them pass, the reporter at 100 % lines**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash -c 'bash tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh --coverage && bash tests/unit/phobos-landlock-filesystem-and-networksystem/run.sh'`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-reporter.c \
  core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-reporter.h \
  core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem.c \
  core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-options.c \
  core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-options.h \
  tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_unit.c \
  tests/unit/phobos-landlock-filesystem-and-networksystem/landlock_filesystem_and_networksystem_unit.c
git commit -m "Arm the reporter on the filesystem enforcer and mark the tasks of its domain"
```

### Task 2.4: The report-only supervisor

**Files:**
- Create: `core/phobos-seccomp-filesystem/phobos-seccomp-filesystem.c` (main), `-filter.c`, `-filter.h`
- Modify: `docker/run_phase/java/Dockerfile` (copy and build `phobos-seccomp-filesystem`, add it to the `readelf` PIE and `BIND_NOW` check), `.github/workflows/build.yml` (the same check in the `run-phase` job)
- Test: `tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_unit.c`

**Interfaces:**
- Consumes: `reporter_handles`, `reporter_service` (Task 2.3), `REPORT_TRAPPED_CALLS` (Task 2.1), `report_summary` (Task 1.2).
- Produces: the binary `phobos-seccomp-filesystem [--verbose] --landlock-bin PATH -- COMMAND [ARGUMENTS...]`, exit status the command's own (guard mapping), 15 when it cannot fork; and

```c
/* Appends the report traps to a filter under construction: one JEQ and one RET USER_NOTIF per
 * call of REPORT_TRAPPED_CALLS. Answers the number of instructions written. */
size_t append_report_traps(struct sock_filter *instructions, size_t room);

/* Proves SECCOMP_USER_NOTIF_FLAG_CONTINUE on this kernel with a throwaway probe child (A.5.6):
 * true only when the probe's trapped getppid was continued and returned this process's number.
 * Lives in -handoff.c, which both supervisors compile. */
bool continue_supported(void);
```

The spike carries the same probe (`denial-report-spike --probe-continue`), and in the ordinary container it reported the continued `getppid` returning the supervisor's process number.

- [ ] **Step 1: Write the failing tests**

With `fork`, `seccomp`, `sendmsg`, `recvmsg`, `ioctl`, `poll`, `waitpid` and the Landlock version query interposed as in the guard's suite: before forking, the supervisor calls `query_landlock_version()` and then `continue_supported()` (A.5.6); when the first answers 0 it prints `Phobos: filesystem denial reporting is off for this run, because this kernel has no Landlock.`, when the second answers false `Phobos: filesystem denial reporting is off for this run, because this kernel cannot continue a supervised call.`, once, and execs the command itself, installing no filter (unit cases: version 0; version 8 with the probe's `SECCOMP_IOCTL_NOTIF_SEND` answering `EINVAL`; in both no report filter is installed, the command is exec'd and its status passed through). Otherwise the child sets `no_new_privs`, installs a filter whose instructions are the arch check plus `append_report_traps` plus `ALLOW`, hands the listener up and execs; the parent receives it, sets `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP` (and on `EINVAL` prints `Phobos: this kernel cannot wake the reporter synchronously, so reporting is slower.` once and goes on), serves notifications with `reporter_service`, forks the drainer when its child has ended, prints the summary and ends with the child's status; `EBUSY` from `seccomp` in the child makes the child print `Phobos: filesystem denial reporting is off for this run, because another supervisor already holds the run's listener.`, close the socket and exec the command, and the parent then only waits and forwards signals.

```c
static void test_ebusy_runs_the_command_unsupervised(void) {
    fake_seccomp_result(-1, EBUSY);
    int status = run_supervisor_main("--", "/bin/true");
    CHECK(status == 0);
    CHECK(exec_was_called_with("/bin/true"));
    CHECK(strstr(captured_stderr(), "filesystem denial reporting is off for this run") != NULL);
}

static void test_the_drainer_keeps_continuing_after_the_child(void) {
    fake_child_exits_with(3);
    fake_pending_notification(__NR_openat, 99);
    int status = run_supervisor_main("--", "/bin/true");
    CHECK(status == 3);
    CHECK(drainer_was_forked());
    CHECK(drainer_answered_only_continue());
}
```

- [ ] **Step 2: Run and see them fail**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh`
Expected: link errors.

- [ ] **Step 3: Implement**

Reuse the guard's `send_descriptor`, `receive_descriptor`, `reap_command` and `exit_code_from_status` by moving them into a small shared source both binaries compile (`core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-handoff.c`), not by copying. The report-only filter does not trap `sendmsg`, so the guard's bootstrap exception and lockout are not needed here. Signals are forwarded exactly as `phobos-seccomp-networksystem.c` does.

- [ ] **Step 4: Run and see them pass at 100 % lines; build the image and see the `readelf` check pass**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_run.sh --coverage`, then the image build from the top of Part B.
Expected: pass; the build prints `Type: DYN` and `BIND_NOW` for the new binary.

- [ ] **Step 5: Lint and commit**

```bash
find docker -name 'Dockerfile*' -type f -exec sh -c 'hadolint --config .hadolint.yaml < "$1"' _ {} \;
git add core/phobos-seccomp-filesystem/phobos-seccomp-filesystem.c \
  core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-filter.c \
  core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-filter.h \
  core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-handoff.c \
  core/phobos-seccomp-filesystem/phobos-seccomp-filesystem-handoff.h \
  docker/run_phase/java/Dockerfile .github/workflows/build.yml \
  tests/unit/phobos-seccomp-filesystem/seccomp_filesystem_unit.c
git commit -m "Add the report-only supervisor the filesystem layer runs when the network layer is off"
```

### Task 2.5: Wire it into the filesystem layer and prove both directions in the image

**Files:**
- Modify: `core/phobos-filesystem.sh`, `core/phobos.sh` (pass `--no-own-reporter` to the filesystem layer when the network layer is on), `core/phobos-tools-common/phobos-constants.sh`
- Create: `tests/integration/protection-matrix/reporting.sh`
- Modify: `tests/integration/protection-matrix/run-all.sh` (run the new suite), `tests/integration/protection-matrix/README.md` (list it)

The suite lives in the protection matrix because the matrix already gives every case its three partners (an unprotected control, the protected run, and the run with only the responsible layer off), compiles the probe that prints `OP <name> ret=<n> errno=<NAME>` for each operation, and installs a minimal base policy for its duration.

**Interfaces:**
- Consumes: the binary from Task 2.4.
- Produces: filesystem-layer options `--reporter-bin <path>` (default beside the script) and `--no-own-reporter`; the chain `REPORTER -- [RESOURCE_LAYER SPEC --] LANDLOCK --mark-reported-domain ARGS -- CMD`.

- [ ] **Step 1: Write the failing suite**

```bash
#!/usr/bin/env bash
# Denial reporting through phobos.sh and the standalone filesystem layer. Every case compares the probe's
# own result (return value and errno) with and without the reporter, so the reporter is shown to change
# nothing, and then requires either success and no line, or the same refusal and exactly one line.
# Run inside the run-phase image, in an ordinary container. See lib.sh for what makes a denial count.
set -uo pipefail
PM_HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${PM_HERE}/lib.sh"
pm_setup || finish
trap pm_restore EXIT
P="$PM/bin/pprobe"
PREFIX='Phobos Security Error: the program tried to illegally '
SUFFIX=' but was blocked by Phobos.'
cd "$PM/work" || exit 1
rm -rf "$PM"/rw/* "$PM"/rw2/* 2>/dev/null
printf 'RW-OK\n' > "$PM/rw/data.txt"

c_rw="$(cfg rw <<EOF2
[read]
$PM/rw
$PM/ro
[write]
$PM/rw
EOF2
)"

# Runs the standalone filesystem layer with the arguments given, under the watchdog, into PM_OUT, PM_ERR
# and PM_STATUS, as run_pm does for phobos.sh.
run_layer() {
  PM_OUT="$PM/out/last.out"
  PM_ERR="$PM/out/last.err"
  timeout --kill-after=5 "$WATCHDOG_SECONDS" phobos-filesystem.sh --tail-flags-file "$PM/tail.flags" "$@" \
    > "$PM_OUT" 2> "$PM_ERR" < /dev/null
  PM_STATUS=$?
}

# Counts the report lines of the last run that name anything under the matrix's own tree, so a line
# about the dynamic loader or the probe's own start-up cannot make a case pass or fail.
own_report_lines() {
  grep "^${PREFIX}" "$PM_ERR" | grep -cF "'$PM/"
}

# reported_case TITLE SWITCHES CONFIG OPNAME ERRNOS LINE -- PROBE ARGS...
# The baseline is the standalone filesystem layer with --no-own-reporter: Landlock alone. The reported run
# is phobos.sh with SWITCHES. Their results for OPNAME must be identical. With ERRNOS empty the operation
# must succeed and no line may name the matrix's tree; otherwise it must fail with one of ERRNOS and LINE
# must appear exactly once, as the only line naming the matrix's tree.
reported_case() {
  local title="$1"
  local switches="$2"
  local config="$3"
  local opname="$4"
  local errnos="$5"
  local line="$6"
  local baseline
  local reported
  shift 7
  pm_prep
  run_layer --no-own-reporter --config "$config" -- "$@"
  baseline="$(op_result "$opname")"
  pm_prep
  if [[ "$switches" == standalone ]]; then
    run_layer --config "$config" -- "$@"
  else
    # SWITCHES is a space-separated list of options, none of which holds a space.
    # shellcheck disable=SC2086
    run_pm $switches --config "$config" -- "$@"
  fi
  reported="$(op_result "$opname")"
  if [[ -z "$baseline" || "$baseline" != "$reported" ]]; then
    bad "$title" "the reporter changed the result: without [${baseline}], with [${reported}] $(pm_describe)"
    return 0
  fi
  if [[ -z "$errnos" ]]; then
    if op_ok "$opname" && [[ "$(own_report_lines)" == 0 ]]; then ok "$title"; else bad "$title" "$(pm_describe)"; fi
    return 0
  fi
  # ERRNOS is a space-separated list of errno names.
  # shellcheck disable=SC2086
  if op_failed_with "$opname" $errnos && [[ "$(grep -cxF "${PREFIX}${line}${SUFFIX}" "$PM_ERR")" == 1 ]] \
    && [[ "$(own_report_lines)" == 1 ]]; then
    ok "$title"
  else
    bad "$title" "expected one line [${line}]: $(pm_describe)"
  fi
}

for switches in "" "-nnr" "-ntr" "-nrr" "-nnr -ntr" "-nnr -nrr" "-ntr -nrr" "-nnr -ntr -nrr" standalone; do
  reported_case "granted read [${switches}]" "$switches" "$c_rw" read "" "" -- "$P" read "$PM/rw/data.txt"
  reported_case "refused read [${switches}]" "$switches" "$c_rw" read "EACCES" \
    "read the File '$PM/none/secret.txt'" -- "$P" read "$PM/none/secret.txt"
  reported_case "granted write [${switches}]" "$switches" "$c_rw" write "" "" -- "$P" write "$PM/rw/data.txt"
  reported_case "refused write [${switches}]" "$switches" "$c_rw" write "EACCES" \
    "write the File '$PM/ro/data.txt'" -- "$P" write "$PM/ro/data.txt"
done

# With the filesystem layer off nothing is refused, so nothing is reported.
run_pm --no-filesystem-restriction --config "$c_rw" -- "$P" read "$PM/none/secret.txt"
if op_ok read && [[ "$(own_report_lines)" == 0 ]]; then ok "-nfr reports nothing"; else bad "-nfr reports nothing" "$(pm_describe)"; fi

finish
```

The ninth entry of the loop, `standalone`, runs the reported run through the standalone filesystem layer, which starts its own reporter, so every action below is proved through it too. Add `reported_case` rows, each under all nine entries, for: create (`mkdir`, `open` with `O_CREAT` through `write` on a new name), delete (`unlink`, `rmdir`), `rename` and `link` across `rw` and `rw2` (move, link), `renameat2_exchange`, `exec` of `$PM/none/pprobe-static` (execute) against `$PM/ro/pprobe-static` (granted), `mkfifo` and `mksock` (create-ipc), `symlink` (create-symlink), `mknod_char` (create the Device), `truncate` (write), and the named-as case through a symbolic link in `rw` pointing into `none`. Further cases, run once each:

- **Volume.** A probe loop of 2000 refused reads prints one line and `filesystem=2000. (PHB-EDENY)`; 150 distinct refused names print 100 lines, the overflow notice, and `filesystem=150`.
- **Quoting.** A refused create of `$'rw2/x\nname'` under a policy that does not grant `rw2` prints `create the File $'<PM>/rw2/x\nname'`.
- **Membership.** The layers read `/var/tmp/opt/core` before the restriction, and the minimal base does not grant it: no line names it. While a probe `sleep` runs, every process under the supervisor that is not a descendant of the enforcer has the `Seccomp_filters` count recorded at arming (read from `/proc`, outside the run).
- **Supervisor gone.** A probe that reads a granted file once a second; the test kills `phobos-seccomp-filesystem` with `SIGKILL` from outside the run; the next granted and the next refused read both fail with `ENOSYS`, and neither succeeds.
- **Standalone network layer** reports no filesystem line, and `-nfr` with the network layer on reports no filesystem line.
- **Rename and link cost.** A probe loop of 10 000 renames within `rw` is timed with and without the reporter; the result is recorded in the suite's output, not gated.

- [ ] **Step 2: Build the image and see the suite fail**

Run: the image build from the top of Part B, then `docker run --rm --network none --memory 3g --pids-limit 1024 -v "$PWD/tests:/tests:ro" phobos-run-phase:local bash /tests/integration/protection-matrix/run-all.sh reporting`
Expected: the refused cases fail on the missing line (no reporter is started yet); every result comparison passes.

- [ ] **Step 3: Implement the wiring**

In `phobos-filesystem.sh`, parse `--reporter-bin` and `--no-own-reporter` (both added to `LAYER_FLAGS` for the standalone re-run and to the manual), and when Landlock applies and `--no-own-reporter` was not given, put the reporter in front of the resource layer and pass the marker to the enforcer:

```bash
reporter_prefix=()
if (( ! NO_OWN_REPORTER )); then
  REPORTER="${REPORTER_BIN_OPT:-${HERE}/phobos-seccomp-filesystem}"
  if [[ -f "$REPORTER" && -x "$REPORTER" ]]; then
    reporter_prefix=( "$REPORTER" )
    if (( PHB_DEBUG_ENABLED )); then reporter_prefix+=( --verbose ); fi
    reporter_prefix+=( --landlock-bin "$LANDLOCK" -- )
  else
    _log "NOTICE: the denial reporter '${REPORTER}' is missing, so blocked filesystem actions are enforced but not reported in this run."
  fi
fi
args=( --mark-reported-domain "${args[@]}" )
```

and run `"${reporter_prefix[@]}" "${limit_prefix[@]}" "${LANDLOCK}" "${args[@]}" -- "${CMD[@]}"`. A missing reporter is a notice, not a refusal (A.5.6). In `phobos.sh`, add `--no-own-reporter` to `fs_flags` when `enable_network` is set (the guard reports from PR 3 on; until then a run with the network layer on reports no filesystem line, so in this task the suite's loop runs only the switch sets that contain `-nnr` and `standalone`, and Task 3.2 widens it to all nine entries). Update the manuals of both scripts.

- [ ] **Step 4: Rebuild and see the suite pass**

Run: the build, then the suite as in Step 2.
Expected: every case passes for the four switch sets with `-nnr`, for `standalone`, and the `-nfr` case.

- [ ] **Step 5: Lint and commit**

```bash
find . -name '*.sh' -type f -print0 | xargs -0 shellcheck -x -S warning
awk 'FNR==1{p=""} /^[a-zA-Z_][a-zA-Z0-9_]*\(\)/{if(p !~ /^[[:space:]]*#/){print FILENAME":"FNR; e=1}} {p=$0} END{exit e}' core/*.sh core/phobos-tools-*/*.sh
git add core/phobos-filesystem.sh core/phobos.sh core/phobos-tools-common/phobos-constants.sh \
  tests/integration/protection-matrix/reporting.sh \
  tests/integration/protection-matrix/run-all.sh \
  tests/integration/protection-matrix/README.md
git commit -m "Report blocked filesystem actions when the network layer is off"
```

## PR 3: The guard reports

### Task 3.1: The guard prints its own refusals in the format

**Files:**
- Modify: `core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-supervisor.c`, `-datagram.c`, `-diagnostics.c`, `-diagnostics.h`
- Modify: `tests/unit/phobos-seccomp-networksystem/seccomp_networksystem_unit.c`, `seccomp_networksystem_run.sh` (link the message module)

**Depends on:** the PR of PR 162's plan that introduces the guard's endpoint formatter (A.8.1). This PR is based on it.

**Interfaces:**
- Consumes: `report_blocked`, `report_summary` (Task 1.2); the endpoint formatter PR 162's plan introduces in `core/phobos-seccomp-networksystem/`, used under the name and signature that PR gives it.
- Produces: `void report_refused_endpoint(const char *verb, const struct sockaddr *address, socklen_t length, bool datagram);` in `-diagnostics.c`, which appends ` over TCP` or ` over UDP` to the formatter's output and calls `report_blocked(REPORT_LAYER_NETWORK, verb, "Endpoint", text, false, NULL)`.

- [ ] **Step 1: Write the failing tests**

For each refusal path the suite already drives (`test_service_paths`, `test_egress_syscalls`), assert the new line beside the existing errno, for example:

```c
static void test_refused_connect_is_reported(void) {
    load_rules_text("allow 127.0.0.1:80\n");
    capture_stderr_begin();
    drive_connect("10.0.0.1", 443);
    CHECK(last_answer_error == -EACCES);
    CHECK(strstr(capture_stderr_end(), "Phobos Security Error: the program tried to illegally "
                 "connect to the Endpoint 10.0.0.1:443 over TCP but was blocked by Phobos.\n") != NULL);
}

static void test_allowed_connect_is_silent(void) {
    load_rules_text("allow 127.0.0.1:80\n");
    capture_stderr_begin();
    drive_connect("127.0.0.1", 80);
    CHECK(last_answer_error == 0);
    CHECK(strstr(capture_stderr_end(), "Phobos Security Error") == NULL);
}
```

and one each for a refused datagram send ("send to ... over UDP"), a raw socket ("open the Socket Type raw (AF_INET, SOCK_RAW)"), a UNIX connect ("connect to the Socket File '...'"), and a listen on an unbound socket ("listen on the Port chosen by the kernel over TCP"); and one per site of the "not reported" group of A.8.1, each answering the same errno as before and printing no `Phobos Security Error` line: an unreadable address, a send on a socket the guard does not hold, a send with ancillary data, an onward `ECONNREFUSED`.

- [ ] **Step 2: Run and see them fail**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/unit/phobos-seccomp-networksystem/seccomp_networksystem_run.sh`
Expected: the new assertions fail; the existing ones pass.

- [ ] **Step 3: Implement**

At each `answer(..., -EACCES)` that is a policy refusal, call the reporter first; keep `log_verbose`. `main` calls `report_summary()` after `reap_command`.

- [ ] **Step 4: Run with `--coverage` and see 100 % lines**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/unit/phobos-seccomp-networksystem/seccomp_networksystem_run.sh --coverage`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-supervisor.c \
  core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-datagram.c \
  core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-diagnostics.c \
  core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-diagnostics.h \
  tests/unit/phobos-seccomp-networksystem/seccomp_networksystem_unit.c \
  tests/unit/phobos-seccomp-networksystem/seccomp_networksystem_run.sh
git commit -m "Have the connect guard report every refusal it makes"
```

### Task 3.2: The guard carries the report traps, bind ports included

**Files:**
- Modify: `core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-child.c` (filter), `-supervisor.c` (dispatch), `-options.c`, `-options.h` (`--report-filesystem`), `phobos-seccomp-networksystem.c`
- Modify: `core/phobos-networksystem.sh` (pass `--report-filesystem` when given it), `core/phobos.sh` (give it to the network layer when the filesystem layer is on)
- Modify: `docker/run_phase/java/Dockerfile` (the guard's `gcc-14` line also compiles the reporter sources and the enforcer's diagnostics-free `-policy.c`, `-path-rule.c` and `-model.c`, never its `-diagnostics.c`, `-options.c` or `-ruleset.c`), `tests/unit/phobos-seccomp-networksystem/seccomp_networksystem_run.sh` (the same sources in `MODULES`)
- Modify: `tests/unit/phobos-seccomp-networksystem/seccomp_networksystem_unit.c`, `tests/integration/protection-matrix/reporting.sh` (the loop over all nine entries, and the network cases), `tests/integration/landlock-filesystem-and-networksystem-acceptance/bind-port-test.sh`

**Interfaces:**
- Consumes: `append_report_traps`, `reporter_handles`, `reporter_service`, `reporter_use_socket_types` (Tasks 2.3, 2.4).

- [ ] **Step 1: Write the failing tests**

Unit: with the Landlock version query answering 0, and again with it answering 8 but the `CONTINUE` probe's send answering `EINVAL`, the guard's filter equals today's instruction by instruction, with and without `--report-filesystem`. With both checks passing, the guard's filter, built with `--report-filesystem`, returns `SECCOMP_RET_USER_NOTIF` for every call of `REPORT_TRAPPED_CALLS` and still returns what it returned before for every other number (run the BPF program with a small interpreter over `seccomp_data` for each syscall number from 0 to 500, with and without the flag, and compare the two outcomes: they may differ only on the report set); without the flag it traps `bind` and `landlock_restrict_self` only, beside its existing set. `service_one` hands a report-trap notification to `reporter_service` and never to the enforcement code. Unit: a send with `MSG_FASTOPEN` keeps its existing `EACCES` and prints no `Phobos Security Error` line. Protection matrix: the loop of `reporting.sh` runs all nine entries; new network cases show that a refused `tcp` connect and a refused `bind 8080` still fail with exactly the errno `network.sh` already pins for them (the guard's decision code is unchanged; the comparison is against that suite's expectation rather than a second guard build) and print one line each, a granted loopback connect keeps its result and prints nothing, and `-nfr` with the network on prints the `bind` line and no filesystem line.

- [ ] **Step 2: Run and see them fail**

Run: both suites as above.
Expected: the filter comparison and the new acceptance rows fail.

- [ ] **Step 3: Implement**

The guard calls `query_landlock_version()` and `continue_supported()` (A.5.6) in `main` before it forks. When either fails, the guard builds exactly today's filter, with no report trap at all (not even `bind` or `landlock_restrict_self`, which are report traps too), and with `--report-filesystem` prints the "reporting is off for this run" notice once; a unit case compares that filter instruction by instruction with today's. When both pass, insert the report traps (or only `bind` and `landlock_restrict_self` without `--report-filesystem`) after the existing `GUARD_TRAP_SYSCALL` lines and before the `sendto` block, so the jump distances of the `sendto` and `sendmsg` blocks stay local to them, and build the program into an array sized for the larger variant. `service_one` first asks `reporter_handles(request)`. `reporter_use_socket_types` gets a function over the guard's `lookup_socket_type` and `fd_socket_inode`. The guard takes `--landlock-bin PATH` and hands it to `reporter_configure`; `phobos-networksystem.sh` adds `--landlock-bin "$LANDLOCK_BIN"` to `guard_command`, the same value it gives its own enforcer and that `phobos.sh` gives the filesystem layer. In `phobos.sh`:

```bash
if (( enable_filesystem )); then network_flags+=( --report-filesystem ); fi
if (( enable_network )); then fs_flags+=( --no-own-reporter ); fi
```

- [ ] **Step 4: Run every suite, the protection matrix included, and see them pass**

Run: the unit suites with `--coverage`, the image build, `run-tests.sh` and `tests/integration/protection-matrix/run-all.sh` in the image; then time the shipped Java acceptance exercise (`tests/integration/landlock-filesystem-and-networksystem-acceptance/phase-test.sh`) five times with this PR's image and five times with `main`'s, and record median and range in the pull request.
Expected: pass; the protection matrix's containment results are identical to `main`'s.

- [ ] **Step 5: Commit**

```bash
git add core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-child.c \
  core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-supervisor.c \
  core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-options.c \
  core/phobos-seccomp-networksystem/phobos-seccomp-networksystem-options.h \
  core/phobos-seccomp-networksystem/phobos-seccomp-networksystem.c \
  core/phobos-networksystem.sh core/phobos.sh \
  tests/unit/phobos-seccomp-networksystem/seccomp_networksystem_unit.c \
  tests/unit/phobos-seccomp-networksystem/seccomp_networksystem_run.sh \
  docker/run_phase/java/Dockerfile \
  tests/integration/protection-matrix/reporting.sh \
  tests/integration/landlock-filesystem-and-networksystem-acceptance/bind-port-test.sh
git commit -m "Let the connect guard report blocked filesystem actions and bind ports"
```

## PR 4: Timeout and resource lines, and the heuristic counter retired

### Task 4.1: The timeout line

**Files:**
- Modify: `core/phobos-timeoutsystem.sh`, `tests/integration/timeout_escalation.sh`

- [ ] **Step 1: Write the failing test**

```bash
OUT="$(bash "$CORE_X/phobos-timeoutsystem.sh" --timeout-bin timeout --pgroup-lock-bin "$LOCK" "$SPEC" -- sleep 30 2>&1)"
check "a timed-out run prints the line" "1" \
  "$(grep -cxF 'Phobos Security Error: the program tried to illegally exceed the Time Limit of 2 seconds but was blocked by Phobos.' <<< "$OUT")"
OUT="$(bash "$CORE_X/phobos-timeoutsystem.sh" --timeout-bin timeout --pgroup-lock-bin "$LOCK" "$SPEC" -- bash -c 'exit 124' 2>&1)"
check "a command's own 124 prints no line" "0" "$(grep -c 'Phobos Security Error' <<< "$OUT")"
```

(`$SPEC` carries a `timeout` of 2 seconds, as the suite's existing cases build it.)

- [ ] **Step 2: Run and see it fail**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/integration/timeout_escalation.sh`
Expected: the first check fails.

- [ ] **Step 3: Implement**

Immediately before `report "Timed out after ${timeout_sec}s. (PHB-ETIMEOUT)"`:

```bash
  report "Phobos Security Error: the program tried to illegally exceed the Time Limit of ${timeout_sec} seconds but was blocked by Phobos."
```

- [ ] **Step 4: Run and see it pass**

- [ ] **Step 5: Commit**

```bash
git add core/phobos-timeoutsystem.sh tests/integration/timeout_escalation.sh
git commit -m "Have the timeout layer print the blocked-action line"
```

### Task 4.2: The resource lines

**Files:**
- Modify: `core/phobos-filesystem.sh`, `core/phobos-tools-common/phobos-constants.sh` (`PHB_STATUS_SIGXCPU=152`, `PHB_STATUS_SIGXFSZ=153`), `tests/integration/resource_limits.sh`

- [ ] **Step 1: Write the failing test**

```bash
OUT="$(run_limited 'cpu = 1' -- bash -c 'while :; do :; done' 2>&1)"
check "a CPU limit hit prints the line" "1" \
  "$(grep -cxF 'Phobos Security Error: the program tried to illegally exceed the CPU Time Limit of 1 seconds but was blocked by Phobos.' <<< "$OUT")"
OUT="$(run_limited 'fsize_mb = 1' -- bash -c 'head -c 2000000 /dev/zero > /tmp/big' 2>&1)"
check "a file size limit hit prints the line" "1" \
  "$(grep -cxF 'Phobos Security Error: the program tried to illegally exceed the File Size Limit of 1 MB but was blocked by Phobos.' <<< "$OUT")"
OUT="$(run_limited 'cpu = 1' -- true 2>&1)"
check "a run within its limits prints nothing" "0" "$(grep -c 'Phobos Security Error' <<< "$OUT")"
```

`run_limited` is the suite's existing helper that writes a configuration with the given limit and runs `phobos.sh -ntr -nnr` over it.

- [ ] **Step 2: Run and see it fail**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/integration/resource_limits.sh`

- [ ] **Step 3: Implement**

After `rc` is known in `phobos-filesystem.sh`, with a new documented function in `core/phobos-tools-common/phobos-log.sh`:

```bash
# Prints the blocked-action line for a resource limit the command's status shows it hit: a CPU
# limit for status 152 (SIGXCPU) and a file size limit for 153 (SIGXFSZ), each only when the
# limits file names that limit. Assumes limits.conf was validated by read_limits_conf and that the
# status is the command's, which a shell cannot tell apart from the same number given to exit.
report_resource_limit_hit() {
  local status="$1"
  local cpu="$2"
  local fsize_mb="$3"
  if (( status == PHB_STATUS_SIGXCPU )) && [[ -n "$cpu" && "$cpu" != 0 ]]; then
    report "Phobos Security Error: the program tried to illegally exceed the CPU Time Limit of ${cpu} seconds but was blocked by Phobos."
  elif (( status == PHB_STATUS_SIGXFSZ )) && [[ -n "$fsize_mb" && "$fsize_mb" != 0 ]]; then
    report "Phobos Security Error: the program tried to illegally exceed the File Size Limit of ${fsize_mb} MB but was blocked by Phobos."
  fi
}
```

called as `report_resource_limit_hit "$rc" "${validated_limits[cpu]:-}" "${validated_limits[fsize_mb]:-}"` when `--resources-layer` was given, in both the Landlock and the `--no-landlock` branch.

- [ ] **Step 4: Run and see it pass**

- [ ] **Step 5: Commit**

```bash
git add core/phobos-filesystem.sh core/phobos-tools-common/phobos-constants.sh \
  core/phobos-tools-common/phobos-log.sh tests/integration/resource_limits.sh
git commit -m "Report a CPU or file size limit the command hit"
```

### Task 4.3: Retire the heuristic counter, and document

**Files:**
- Modify: `core/phobos-filesystem.sh` (remove the `tee`/`count_denials` pipe and the report after the command), `core/phobos-tools-common/phobos-log.sh` (remove `count_denials` and the two patterns), `core/phobos-tools-common/phobos-constants.sh` (remove the counter's bounds), `tests/integration/denial_report.sh` (rewritten), `README.md`, `SECURITY.md`, `CLAUDE.md` (project structure: the new directory and binary)

- [ ] **Step 1: Rewrite the failing test**

`denial_report.sh` keeps its stand-in enforcer and pins the new contract: a command that prints `Permission denied` itself produces no summary (nothing was blocked), the command's stderr still passes through unchanged and its status is unchanged, and a process the command leaves behind no longer delays the end of the run by the old grace period.

- [ ] **Step 2: Run and see it fail**

Run: `docker run --rm -v "$PWD:/w" -w /w phobos-test-runner bash tests/integration/denial_report.sh`
Expected: the first check fails (the old counter still prints `filesystem=1`).

- [ ] **Step 3: Implement**

Remove the counter; the command's standard error goes straight to the layer's. Update the manuals ("WHAT IT REPORTS"), the README's description of the output, and SECURITY.md's statement of what is reported and what is not (A.10).

- [ ] **Step 4: Run every suite and every lint job**

Run: every command of the CLAUDE.md lint block, the unit suites, the integration suites in the test runner, and the acceptance and protection-matrix suites in the image.
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add core/phobos-filesystem.sh core/phobos-tools-common/phobos-log.sh \
  core/phobos-tools-common/phobos-constants.sh tests/integration/denial_report.sh \
  README.md SECURITY.md CLAUDE.md
git commit -m "Count blocked actions where they are blocked, and retire the stderr heuristic"
```

---

# Part C: Review record

The plan was reviewed read-only (no shell, no edits) in one session of eight rounds. Each finding, and what became of it:

**Turn 1** (10 findings, verdict: not approved).

1. *High, supervisor death changes granted calls (`ENOSYS`).* Accepted: the guarantee is narrowed to "never grants; changes no outcome while the supervisor runs", the failure mode is stated (A.5.6) and tested (Task 2.5). It is the guard's existing property.
2. *High, truncation below ABI 3.* Disputed and resolved: below ABI 3 Landlock does not handle truncation at all, and `O_TRUNC` needs `WRITE_FILE`, so masking by the handled rights reproduces both ABIs; reasoning added to A.5.4 with a model test at versions 2 and 3. The reviewer accepted this in turn 2.
3. *High, missing enforcer diagnostics in the guard's link.* Accepted and widened: both modules define `log_verbose`, so a diagnostics-free `-policy.c` holds everything the model needs (Task 1.1), with a link test.
4. *Medium, the parent shown instead of the object.* Accepted: separate rights anchor and shown path (Task 2.2).
5. *Medium, filter count not a unique marker.* Accepted with scope: the invariant "no process outside the domain installs a filter" is stated (A.5.3) and tested (Task 2.5).
6. *Medium, mirror gaps.* Accepted: `openat2` resolve flags, `O_TMPFILE`, deleted or unreachable directories are excluded by construction (A.5.4, A.10).
7. *Medium, acceptance does not prove both directions.* Accepted: the protection-matrix suite `reporting.sh` compares each operation's result with and without the reporter (Task 2.5).
8. *Medium, contract versus de-duplication.* Accepted: the contract is one line per distinct blocked action (Goal, A.7).
9. *Medium, the spike underestimates the mirror.* Answered with data: per-call counts show the spike judged every notification of the measured workloads; spreads added (A.4.2); a rename loop and the shipped exercise are timed in the implementation.
10. *Low, network `EACCES` classification.* Accepted: every guard answer site is classified (A.8.1). The endpoint formatter comes from PR 162's plan.

**Turn 2** (all ten answers accepted, some with scope notes; 5 new findings, verdict: not approved).

1. *High, arming would ignore the filesystem enforcer after the network one.* Accepted: an explicit three-state machine with a caller check on `/proc/<pid>/exe` (A.5.3), unit cases and a full-chain case.
2. *Medium, the summary promised more than it counts.* Accepted: A.7 now states exactly what is counted and what is not.
3. *Medium, flag combinations underspecified.* Accepted: a whitelist of judged flags, silence for everything else, and silence for calls that fail before Landlock (existence, `EEXIST`, discretionary access through `faccessat` with the command's own credentials, type mismatch) (A.6.4), each pinned by a unit case.
4. *Medium, `MSG_FASTOPEN` had no implementation path.* Accepted by reclassifying it as not reported: the guard refuses the flag before it reads a destination, so there is no judged endpoint.
5. *Low, this record was a placeholder.* Filled in.

**Turn 3** (the turn-2 fixes accepted; 5 new findings, verdict: not approved).

1. *High, `CONTINUE` not preflighted.* Accepted: report traps are added only when the kernel has Landlock (Linux 5.13, which implies `CONTINUE` from 5.5); otherwise the guard keeps exactly today's filter and the report-only supervisor runs the command without a filter (A.5.6), with a unit case.
2. *Medium, the command may change its credentials.* Accepted: the supervisor compares `Uid`, `Gid`, `Groups` and `CapEff` of the task with its own and stays silent on any difference before trusting `faccessat` (A.6.4), with a unit case.
3. *Medium, pre-emptions of whitelisted flags.* Accepted: `ELOOP` for `O_NOFOLLOW` and `AT_SYMLINK_NOFOLLOW` on a final link is silent, `O_NOATIME` moved to the silent column, and every existing-target pre-emption has its own unit case.
4. *Medium, standalone coverage overstated.* Accepted: the suite's loop has a ninth entry, `standalone`, so every action row is proved through the standalone filesystem layer.
5. *Low, `MSG_FASTOPEN` not pinned.* Accepted: a unit case keeps its `EACCES` and no line.

**Turn 4** (the turn-3 answers accepted; 1 finding, verdict: not approved).

1. *The `CONTINUE` preflight was not carried into the tasks.* Accepted: Task 2.4 queries the Landlock version before forking and execs the command without a filter at 0; Task 3.2 builds exactly today's guard filter at 0 (no report trap at all, `bind` and `landlock_restrict_self` included) and compares it instruction by instruction; the stale "old kernel without `CONTINUE`" case is gone from A.5.6.

**Turn 5** (1 finding, verdict: not approved).

1. *A Landlock version does not prove `CONTINUE` on a vendor kernel with a backport.* Accepted: `continue_supported()` proves it directly with a throwaway probe child before the command is forked (A.5.6, Tasks 2.4 and 3.2), with a unit case for a positive Landlock version and a refused `CONTINUE`. The spike carries the probe and it passed in the ordinary container, alone and under `phobos.sh -nnr`.

**Turn 6** (1 finding, verdict: not approved).

1. *The probe would hang when the send fails, because the child stays blocked in its trapped call.* Accepted and fixed in the spike: the supervisor waits for the notification with a one-second `poll` and closes the listener before reading the probe's result, which releases the probe with `ENOSYS`. Measured: a build answering with an invalid flag reported "unsupported" at once with no hang. A.5.6 and the unit cases (including a `poll` timeout) now require it.

**Turn 7** (1 finding, verdict: not approved).

1. *A probe that cannot install or hand over its listener made the supervisor exit.* Accepted and fixed in the spike: a failed socket pair, fork or handoff is "unsupported", with the descriptors closed and the probe reaped. Measured: beneath the guard's listener the probe answered "unsupported" (probe status 3). A.5.6 and the unit cases cover each path.

**Turn 8.** No further finding. The verdict, verbatim: "I approve this plan."
