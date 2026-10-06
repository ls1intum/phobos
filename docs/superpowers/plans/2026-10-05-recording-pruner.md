# Recording Pruner Implementation Plan

> **How to execute:** work through Part B one task at a time, test first, with a review between tasks. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A second pruner, beside the layer pruner of PR 162, that blocks nothing: it records every path a program touches (with the kind of access) and every network endpoint it reaches, while a person uses the program interactively with a real terminal, and turns one or more such sessions into a Phobos configuration that `phobos-policysystem.sh` accepts and under which the same sessions run through the real layers with no denial.

**Architecture:** A Python tool, `phobos-record`, in the prune image of PR 162 and nowhere else. It runs the program under `strace -DDD` (the tracer detached as a grandchild, so the program stays the calling shell's own child and keeps the terminal, job control and signals), with the observer options, the parser and the generalisation rules shared with PR 162 rather than copied. Each successful call is mapped to the policy section Landlock would check for it, names are recovered from the TLS host name and from DNS answers, and the result is written through PR 162's configuration renderer. A `check` mode replays a session under `phobos.sh` with the generated configuration and an empty base, and fails on every call that succeeded while recording and is refused now.

**Tech Stack:** Python 3 (standard library only), bash for the entry script and the suites, `strace` from the distribution archive (already in PR 162's prune image), the existing `phobos.sh` layers and C enforcers, Docker, pytest for unit tests, the repository's shell harness for integration tests.

**Spec:** Part A of this document. As in PR 162, the request, the research and the design live in the plan file itself, and the spike that Part A quotes lives beside it in `docs/superpowers/plans/2026-10-05-recording-pruner-spike/`.

## Global Constraints

- British English in all prose, comments, messages, workflow and step names.
- No em dashes anywhere; prefer a comma, a full stop or brackets over a hyphen.
- One variable, field or function declaration per line, in every language (no `a, b = ...`, no `int x, y;`).
- Every text file LF, final newline, no trailing whitespace outside Markdown, spaces not tabs.
- No `--privileged`, `--cap-add` or `--security-opt` for any suite, for the recording container or for the replay container.
- Never add a bind, a capability or an allowed host to make a test pass.
- Nothing under `core/` changes. The recorder is never reachable from `phobos.sh` or any layer script, and neither `strace` nor the recorder is ever in the run-phase (grading) image.
- The recorder grants everything while it records. It is for the instructor's reference program only, never for an untrusted submission, and every output it writes says that it was recorded, from how many sessions, and that it covers only what those sessions exercised.
- The recorder never removes anything from an existing policy on its own; `diff` only lists.
- Generated configuration must be accepted by `core/phobos-policysystem.sh` as it stands on `main`, as an exercise configuration (absolute paths, no `*`, `?` or `[`, existing `[read]`/`[execute]` paths, no nested entry whose rights are a strict subset of an ancestor's).
- Generalisation follows PR 162's rules, through PR 162's code: fine-grained roots `/etc`, `/dev`, `/proc`, `/sys`, `/root`, `/home`, `/run` file by file and never compacted, except per-run names, which get their smallest stable directory and a comment; outside them `[read]` and `[execute]` may widen to the containing directory; write-class rights never widen beyond the directory Landlock checks.
- Limit margins are PR 162's (decision 3): 5x wall clock and CPU time, 2x address space; `mem_mb` is `ulimit -v`.
- Nothing language specific in the recorder; anything language specific lives only in an exercise's own files or in a language configuration.
- Python code is linted by `ruff check --no-cache .` and, under `var/tmp/helpers`, by `bandit --recursive --ini .bandit --severity-level medium docker/prune_phase/orchestrate var/tmp/helpers`; shell by `shellcheck -x -S warning`; Dockerfiles by `hadolint --config .hadolint.yaml`; YAML by `yamllint --strict .`; everything by `ec --no-color`.
- Branch names use an allowed prefix (`feature/`, `ci/`, `docs/`, not `feat/`).

---

# Part A: Design

## A.1 The request

Markus asked for a pruner that blocks nothing: it only records every path the program touches, with the kind of access, and every network endpoint it reaches (connect, send to, bind, listen, accept), and generates a matching Phobos policy from that. Its point is interactive use: a person runs a program with a real terminal, standard input and output passed through, clicks through a tool or types into a REPL, and so learns every path and endpoint it needs. Several sessions can be merged into one policy. In PR 162 this was approach 2 ("learning run"), rejected there as the default pruner; it is now wanted as a separate tool for this interactive purpose, not as a replacement for PR 162.

## A.2 The three plans and what each one observes

| Plan | Phase | Observer | Sees | Decides |
| --- | --- | --- | --- | --- |
| PR 162, prune on the layers | offline, prune image | `strace -f` around `phobos.sh` | every refused call and its errno | grants from attributed denials, then minimises |
| PR 166, denial reporting | online, grading image | the connect guard's seccomp listener (or a report-only one under `-nnr`), `CONTINUE` always, a mirror of Landlock | a trapped call before the kernel runs it, never its result | nothing; prints "Phobos Security Error: ..." |
| this plan, recording pruner | offline, prune image | `strace -DDD -f` around the bare program | every successful call, its result and its output buffers | grants from what succeeded |

There are therefore two observation mechanisms in the project, each where it belongs, and this plan adds no third: `strace` for the two offline tools, with one set of options and one parser (A.3), and the report-only seccomp supervisor for grading. The recorder deliberately does not reuse PR 166's supervisor (A.3.2).

## A.3 The observer

### A.3.1 Chosen: `strace`, shared with PR 162

The recorder runs `strace -DDD -f -qq -yy -x -s 4096 --seccomp-bpf -e trace=<set> -o <file> -- <command>` and parses the log with PR 162's `layer_prune.strace_parse`. Why `strace`:

1. **It sees results.** The recorder grants from successful calls only, so the failed probes every program makes (the `PATH` search, optional configuration files, `nscd`) produce nothing. The spike's sessions failed hundreds of calls with `ENOENT` that a pre-call observer would have had to treat as accesses or model away.
2. **It sees output buffers.** Host names come from DNS answers (`recvfrom`, `recvmsg`) and ephemeral ports from `getsockname` and from `-yy`'s socket decoration; an accepted peer comes from `accept`'s output address. None of these exist before the call.
3. **It resolves the object.** `-yy` decorates every returned descriptor with the path the kernel resolved (`= 3</usr/lib/aarch64-linux-gnu/libc.so.6>` for `openat("/lib/.../libc.so.6")`), and every socket with its local and remote end, which is the object Landlock judged and the endpoint the guard judged.
4. **One parser.** PR 162 already parses this format; the recorder extends that module (Task R2.1) instead of writing a second.

### A.3.2 Rejected: PR 166's report-only seccomp supervisor as a recorder

A recorder is the same machinery as PR 166's supervisor reporting allowed accesses too, so it was considered seriously:

- It sees a call before the kernel runs it, never the result or an output buffer, so it cannot tell a successful open from an `ENOENT` probe, cannot learn a DNS answer, an ephemeral port or an accepted peer, and cannot know whether `O_CREAT` created the file.
- It lives inside the grading chain, sharing the connect guard's single seccomp listener (`EBUSY` for a second one, measured by PR 166). A record mode there would mean a grading binary that can run in "grant everything and log" mode, which is exactly what A.10 forbids: the recorder must not be reachable from `phobos.sh`.
- It mirrors Landlock with a model; the recorder needs no model of what Landlock would decide, only a record of what happened.

Its one advantage, no ptrace and so no effect on a program that traces itself, is listed as a limitation in A.17.

### A.3.3 Interactive use under ptrace, measured

`-DDD` runs the tracer as a grandchild in a session of its own: the program stays the direct child of the calling shell, so the shell's job control acts on the program itself, and terminal signals reach the program's process group, never the tracer. Measured in the spike (A.4) with a pseudo-terminal running `bash -i`, typing into `python3 -q`:

| Interaction | bare | `strace -DDD` | `strace` as parent | under `phobos.sh` (replay) |
| --- | --- | --- | --- | --- |
| Ctrl+C during `time.sleep(60)`: `KeyboardInterrupt`, prompt keeps working | yes | yes | yes | yes, but the traceback is lost (A.19, finding F1) |
| Ctrl+Z: bash reports `Stopped`; `fg` resumes the same Python | yes | yes | yes | yes |
| child processes (`ls`, a `#!/bin/sh` script) | yes | yes | yes | yes |
| standard error still reaches the terminal after Ctrl+C | yes | yes | yes | no (F1) |

`strace` as the parent also passed, but `-DDD` is chosen: it keeps the program's exit status and job state the shell's own, and a Ctrl+C or Ctrl+Z cannot stop or kill the tracer. The tracer is reaped by the recorder, which makes itself a child subreaper (`prctl(PR_SET_CHILD_SUBREAPER)`) so that the double-forked tracer is reparented to it and the recorder knows the log is complete when that child ends.

### A.3.4 The trace set

`%file,%network,%process,ioctl,fchdir,write,setsid,setpgid,io_uring_setup`. `%file` brings every call that names a path, `%network` every socket call, `%process` the process tree; `ioctl` reveals a device ioctl no section can grant, `fchdir` the working directory, `write` the TLS ClientHello on a socket (OpenSSL writes it with `write`, measured), and `setsid`, `setpgid` and `io_uring_setup` are fixed refusals of the grading layers (A.6.3). `ftruncate` is not traced: `[write]` grants `WRITE_FILE` and `TRUNCATE` together, and Landlock decides `ftruncate` from the rights recorded when the descriptor was opened, so the open already produced the grant.

## A.4 Spike

`docs/superpowers/plans/2026-10-05-recording-pruner-spike/` (throwaway, never imported by anything): `Dockerfile` (the run-phase image built from this checkout, plus `strace` 6.8 and `python3` 3.12, standing in for PR 162's prune image), `record.sh`, `recorder.py` (snapshot, a self-contained parser, the mapping, generation, the replay comparison), `drive_session.py` (types a session into a pseudo-terminal running `bash -i`), `containment.py` (the forbidden direction), `in-container.sh` and `run-spike.sh` (one fresh container per mode), `overhead.sh`.

Environment: Docker Desktop, kernel 7.0.14-linuxkit, aarch64, Landlock ABI 8, ordinary containers with no capability added; recording and replay each in a fresh container from the same image.

The session (typed into `python3 -q` at `/var/tmp/testing-dir`, the tail's `--chdir`): read `/etc/hostname` (a fine-grained root) and `/opt/java/openjdk/release`; write a temporary file with a random name and move it over `out.txt`; create a per-run directory `cache/<pid>` and a file in it; delete a pre-existing `old.txt`; create a file in `/tmp` and rename it into the work directory (a cross-directory move); start a TCP server on an ephemeral loopback port in a thread and connect to it; send a datagram between two loopback UDP sockets; run `ls /usr/share/doc` and a `#!/bin/sh` script that runs `cat`; Ctrl+C; Ctrl+Z and `fg`; exit (Python writes `/root/.python_history`). A networked variant also makes an HTTPS request to `example.org`.

Results:

- **Replay with zero denials**, offline and networked. In a fresh container whose base was replaced by an empty one, `phobos-policysystem.sh` accepted the generated configuration, and the same keystrokes under `phobos.sh --config generated.cfg --config <timeout=0 overlay>` (the networked one with `--resolver`) passed every step. A tracer around the replay counted 0 refusals of calls that had succeeded while recording; it counted 4 (6 networked) refusals of calls that had failed while recording too, all `connect` to `/var/run/nscd/socket` (no `nscd` runs, so the recording saw `ENOENT`; under the layers the guard refuses every UNIX connect first). The spike compared calls by name and object only, which is coarser than A.14's access signatures; with no refusal of any recorded object at all, the finer comparison would not have found one either, and every scripted step's marker appeared in the replay, so the session also completed.
- **Forbidden direction**, under the same configuration: `/etc/passwd` and `/var/log/dpkg.log` read, a write into `/usr/share/doc` (read-only), `mkdir /var/tmp/phobos-probe`, `connect 10.0.0.1:80` and `bind 127.0.0.1:8080` were all refused with `EACCES`, while the recorded neighbour `/opt/java/openjdk/release` stayed readable.
- **The generated configuration** (offline): 27 `[read]`, 5 `[execute]`, 4 `[write]`, 3 `[create]`, 2 `[delete]`, 2 `[restructure]` rows, `[connect] allow 127.0.0.1:*` and `allow 127.0.0.1:* udp`, `[bind] allow 0` and `allow 0 udp`. Networked, `allow example.org:443` was added from the TLS host name, the DNS lookups stayed commented out because the network layer maps the name in `/etc/hosts`, and two datagram connects to port 443 that sent nothing (glibc ranking addresses, A.8.4) were listed and not granted. On ABI 8 the UDP rules were accepted because they sit beside the UDP loopback wildcard (`config_doc.txt`).
- **Defects the spike found and fixed, now design rules:**
  1. A first replay failed with `exec python3: Permission denied` although `/usr/bin` had `[execute]`: the kernel opens a binary and its ELF interpreter with `__FMODE_EXEC` for reading, and Landlock's `file_open` hook then asks for `READ_FILE` as well as `EXECUTE`. An executed file therefore needs `[read]` and `[execute]` (A.6.1), as PR 166's A.6.4 also states.
  2. A second replay failed with `chdir /var/tmp/testing-dir: No such file or directory`: `TailPhobos.cfg` runs the command in `/var/tmp/testing-dir`, so a recording made elsewhere describes a different working directory. The recorder runs the program in the tail's `--chdir` (A.5.2).
  3. Splitting strace's argument list by counting angle brackets breaks on `->` in a `-yy` socket decoration (`3<TCP:[a:1->b:2]>`) and on `=>` in strace's in-out length notation (`[128 => 16]`, printed for `getsockname` and `accept` also under `-y`): every later argument merged into one and the TLS host name was missed. Task R2.1 adds both cases to the shared parser's tests, which matters for PR 162 too.
  4. A spec directory beneath a write path is refused (`PHB-EPOLICY`), so the acceptance gate builds its specification under `/var/tmp`, never `/tmp`.
- **Overhead.** Interactive: the recorded steps took 3 to 19 ms against under 2 ms bare, invisible at a keyboard; a recorded session left 800 log lines (115 kB), and the snapshot of the image's 24 530 paths took 0.14 to 0.30 s and 1.6 MB. Non-interactive, median of three runs each, measured twice: `javac` plus `java` of one class 0.255 to 0.277 s bare, 0.409 to 0.420 s with `--seccomp-bpf` (1.5x to 1.6x), 0.692 to 0.718 s without it (2.6x to 2.7x); `cat` of 5000 small files 0.055 s bare, 0.93 to 1.02 s with `--seccomp-bpf` (17x to 19x), 2.86 to 3.03 s without it (52x to 55x). A call-heavy build therefore records much more slowly than it runs; an interactive session does not notice.
- **Two findings about the grading layers**, F1 and F2, each fixed by its own pull request against `core/` (A.19).

## A.5 Architecture

### A.5.1 Components

```
prune image (PR 162, docker/prune_phase/layers/)   FROM run-phase image + strace + python3 + BasePrune.cfg
  plus, from this plan: nothing installed; the recorder is mounted with the helpers

var/tmp/helpers/layer_prune/          PR 162's package; this plan extends, never copies:
  strace_parse.py   + iter_calls(): every completed call, successful ones included (R2.1)
  record.py         + Need: a (objects, sections, run, tid, tgid) record that Denial also yields (R2.2)
  generalise.py     grants_for() and per_run_grants() over Need; session ids for per-run names (R2.2)
  cfgfile.py        + header lines, + comment lines in [connect]/[bind], + read_policy() (R2.3)
  network.py        + loopback_wildcard(), shared by both pruners (R2.3)
  limits.py, sampler.py   used unchanged (R7)

var/tmp/helpers/layer_record/         this plan's package, standard library only
  phobos-record     bash entry script, the only way in (R3)
  main.py           the command line: record, generate, check, diff (R3, R4, R6)
  guard.py          the safety refusals of A.10 (R3)
  observe.py        runs one session under strace -DDD, subreaper, session metadata (R3)
  snapshot.py       the pre-session listing of every path (R3)
  pty_script.py     drives a scripted session through a pseudo-terminal (R3)
  needs.py          successful calls -> Needs, endpoints, names, fixed refusals (R4, R5)
  names.py          DNS answers, TLS ClientHello, /etc/hosts -> address-to-name maps (R5)
  endpoints.py      endpoints -> [connect], [bind], [accept] suggestions (R5)
  generate.py       sessions -> Recording -> policy.cfg and record.json (R4, R5, R6, R7)
  check.py          the replay check of A.14 (R4)
  diff.py           a recording against an existing policy (R6)

docker-compose.yaml   services record and record_networked, profile "record" (R3)
```

### A.5.2 A recording directory, and the commands

A recording lives in one directory, by default under `./var/tmp/recordings/<name>` on the host, mounted at `/var/tmp/recordings`:

```
<name>/
  sessions/<n>/trace          the strace log
  sessions/<n>/session.json   command, start and end time, exit status, interactive (stdin a terminal),
                              container id, kernel, Landlock ABI, strace version, uid, the snapshot it belongs to
  snapshots/<container>.txt   every path that existed before the first session in that container, with its
                              fingerprint (type; mode, size and modification time of a file; target of a link)
  snapshots/<container>.hosts that container's /etc/hosts at the same moment (A.8.3)
  policy.cfg                  written by generate
  record.json                 written by generate: every grant with the calls behind it, every widening,
                              fixed refusals, unsent datagram connects, names and their source
```

- `phobos-record record [--name <name>] [--exercise <dir>] [--script <file>] -- <command> [args...]` copies the exercise (default `/srv/phobos-record-exercise`, when mounted) into the tail's `--chdir` directory on the first session in a container, takes the container's snapshot, then runs the command there under the observer. The terminal is passed through untouched; with `--script` the session is typed from a file instead (A.5.3). It ends with the command's own status.
- `phobos-record generate [--name <name>] [--limits] [--memory-pinned]` reads every session of the recording and writes `policy.cfg` and `record.json`, then passes `policy.cfg` through the acceptance gate (`phobos-policysystem.sh --spec-dir <under /var/tmp> --config policy.cfg`, exercise mode).
- `phobos-record check [--name <name>] [--script <file>] -- <command> [args...]` is the replay check of A.14, run in a fresh container.
- `phobos-record diff [--name <name>]... --policy <cfg>` lists what the sessions needed that the policy lacks and what the policy grants that no session used (A.12).

### A.5.3 Scripted sessions

`--script` takes a plain text file, one action per line, so a session can be repeated exactly and the suites can drive one:

```
# a comment
send import os                         types the text and Enter
expect ^OK-R1                          waits up to 60 s for output matching the regular expression
key ctrl-c                             sends one control character: ctrl-c, ctrl-d, ctrl-z, ctrl-backslash
sleep 1                                waits, in seconds
```

`pty_script` runs the command in a pseudo-terminal and fails the session when an `expect` times out. Job control cannot be scripted this way (it needs an interactive shell around the command), so the integration suite drives `bash -i` itself for the Ctrl+Z case, as the spike did.

### A.5.4 Where it runs, and why only there

In PR 162's prune image, started as an ordinary container: `docker compose --profile record run --rm record record -- <command>` (offline, `network_mode: none`) or the `record_networked` service for a program that must reach hosts. A developer's Linux machine could run `strace` and Python directly, but a recording there describes that machine's filesystem (another JDK path, another libc), which is not the image a submission is graded in, and the replay check needs the image's compiled enforcers. So `phobos-record` refuses to start outside the prune image (A.10); `docker run -it` gives a developer the same terminal anyway.

## A.6 From successful calls to sections

### A.6.1 The mapping

Letters are the enforcer's (`phobos-landlock-filesystem-and-networksystem-path-rule.c`): `[read]` gives `READ_FILE` and `READ_DIR` (and `RESOLVE_UNIX` from ABI 9), `[execute]` `EXECUTE`, `[write]` `WRITE_FILE` and `TRUNCATE`, `[create]` `MAKE_REG` and `MAKE_DIR`, `[delete]` `REMOVE_FILE` and `REMOVE_DIR`, `[create-ipc]` `MAKE_SOCK` and `MAKE_FIFO`, `[create-symlink]` `MAKE_SYM`, `[restructure]` create, delete and `REFER`. No section grants `IOCTL_DEV`, `MAKE_CHAR` or `MAKE_BLOCK`. Only calls that succeeded count; a non-blocking `connect` that answered `EINPROGRESS` counts only once its completion is seen (A.8.1).

| Successful call | Object (the path the kernel resolved, from `-yy`) | Section |
| --- | --- | --- |
| `open`, `openat`, `openat2` with `O_PATH` | | none: an `O_PATH` descriptor carries no access right |
| `openat2` with a non-zero `resolve` field | as `openat`: the resolve flags only restrict the lookup, and `-yy` shows the object the lookup reached | as the rows below |
| `open`, `openat`, `openat2` with `O_TMPFILE` | | unsupported (A.6.4): which right Landlock checks for an unnamed file is not pinned by a test |
| the same, read access, on a file | the file | `[read]` |
| the same, read access, on a directory (then `getdents64`) | the directory | `[read]` (lists it, and makes every file beneath readable: Phobos has no list-only right, A.7) |
| the same, write or read-write access, or `O_TRUNC`, on an existing file | the file | `[write]` (plus `[read]` for read-write) |
| the same with `O_CREAT`, the file new | parent; the new file | `[create]` on the parent, and `[write]` or `[read]` for the access mode on the new file, which A.7 places on the nearest pre-existing ancestor |
| `creat` | as `O_WRONLY|O_CREAT|O_TRUNC` | |
| `truncate` | the file | `[write]` |
| `ftruncate` | | none: decided at open, already granted there |
| `execve`, `execveat` | the binary, its `PT_INTERP` read from the ELF header, and a `#!` interpreter, recursively | `[execute]` and `[read]` on each (A.4, defect 1) |
| `execveat` with `AT_EMPTY_PATH` (`fexecve`) | the path `-yy` shows for the descriptor, then as above | `[execute]` and `[read]`; a descriptor without a path (`memfd:`, deleted) is unsupported (A.6.4) |
| `mkdir`, `mkdirat` | parent | `[create]` |
| `mknod`, `mknodat`, regular file / FIFO or socket / device | parent | `[create]` / `[create-ipc]` / none, a fixed refusal (A.6.3) |
| `symlink`, `symlinkat` | parent of the link | `[create-symlink]` |
| `unlink`, `unlinkat`, `rmdir` | parent | `[delete]` |
| `rename`, `renameat`, `renameat2` within one directory | the directory | the creation section for the object's type, and `[delete]` |
| the same across directories | both parents | `[delete]` on the source parent, the creation section on the destination parent, `[restructure]` on both, and the source parent given every section the destination holds (A.6.2) |
| `renameat2` with `RENAME_EXCHANGE` | both parents | as across directories, in both directions |
| a rename onto an existing name | destination parent | additionally `[delete]` |
| `link`, `linkat` | new parent (and the old one when it differs) | the creation section; across directories `[restructure]` on both and A.6.2 |
| `bind` of a pathname `AF_UNIX` socket | parent | `[create-ipc]` |
| `bind` of an abstract `AF_UNIX` name | | none: no filesystem object; scoped by Landlock to the domain, where the session's own server also runs |
| `connect`, `sendto`, `sendmsg` to a pathname `AF_UNIX` socket | | none: a fixed refusal, the connect guard carries no UNIX family |
| `chdir`, `fchdir`, `stat` family, `access`, `readlink`, `getxattr`, `chmod`, `chown`, `utimensat`, `inotify_add_watch` | | none: Landlock checks no right for them (kernel Landlock documentation) |
| network calls | | A.8 |

Two clarifications the table relies on, both measured or documented:

- `O_CREAT` on a new name needs `MAKE_REG` on the parent and then the open's own right on the new file, because Landlock lets the creation happen and then judges the open (PR 166, A.6.3); the spike's `mkstemp` needed `[create]` and `[write]`.
- A descriptor opened before `landlock_restrict_self` is not restricted (kernel documentation, "Files or directories opened before the sandboxing are not subject to these restrictions"). The terminal on standard input, output and error is inherited, so it needs no grant and is never recorded (it is never opened by the session).

### A.6.2 Moves across directories

Landlock refuses a link or rename across directories unless both parents grant `REFER` and "the reparented file may not gain more access rights in the destination directory than it previously had in the source directory" (kernel documentation). After generalisation, for every recorded move from source parent `S` to destination parent `D`, `S` therefore receives every section `D` holds, repeated until nothing changes, because one directory can be both a source and a destination. This widens `S`, in the spike `/tmp` gained `[read]` and `[execute]` from `/var/tmp/testing-dir`, and the widening is listed in the record.

### A.6.3 Fixed refusals: what grading refuses whatever the policy grants

Recorded and printed as comments at the end of `policy.cfg` and in `record.json`, never granted. Each names the layer that refuses it and, where Landlock does, the Landlock version from which it is refused, because below that version the right is not handled and the call is free (the enforcer says so on every run, `report_unenforceable_rights`); the comment is written against the ABI the recording container reported, and `record.json` keeps the ABI:

- a `connect`, `sendto` or `sendmsg` to a pathname or abstract `AF_UNIX` socket outside the session (the connect guard refuses the family, whenever the network layer is on, on every ABI);
- a `socket` of `AF_PACKET`, a raw socket, an ICMP datagram socket (the guard, every ABI);
- `setsid`, `setpgid` (the timeout's group lock whenever a timeout is set, and the guard), and so the job control of an interactive shell recorded as the program;
- `io_uring_setup` (the guard refuses io_uring);
- an `ioctl` other than the ones Landlock always allows (`FIOCLEX`, `FIONCLEX`, `FIONBIO`, `FIOASYNC`, `FIFREEZE`, `FITHAW`, `FIGETBSZ`, `FS_IOC_FIEMAP`, `FICLONE`, `FICLONERANGE`, `FIDEDUPERANGE`, `FS_IOC_GETFSUUID`, `FS_IOC_GETFSSYSFSPATH`) on a character or block device the session opened itself: no section grants `IOCTL_DEV`, so Landlock refuses it from version 5 on; below 5 it is free (on the inherited terminal it stays allowed on every version, as above). A program that reopens `/dev/tty` and sets its modes, a pager or an editor, cannot run the same way at grading time on such a kernel;
- `mknod` of a device node (Landlock, every version that handles the filesystem).

A fixed refusal does not fail `generate`: the instructor learns from it that the program as recorded needs something no policy can give (and `check` fails on it, A.14). The recorder states these refusals; it does not pin a Landlock version for grading, which stays the operator's `--minimum-landlock-version` in the tail flags. A recording on one ABI says nothing about the ABI grading runs on, so a comment never presents a Landlock refusal as guaranteed on a kernel below the version it names.

### A.6.4 Calls the recorder does not map

A successful call whose effect on Landlock the mapping does not state is never silently ignored. It is listed in `record.json` under `unsupported` with the trace line, `generate` writes a header line `INCOMPLETE: <n> recorded calls are not mapped; see record.json`, and ends with `generate.EXIT_INCOMPLETE = 6` after writing the files, so a script cannot mistake the result for a complete one; the replay check (A.14) then shows whether those calls matter under the layers. The list: `O_TMPFILE` opens; an `execveat` with `AT_EMPTY_PATH` on a descriptor without a path; `open_by_handle_at`; any `%file` call the table of A.6.1 does not name (a new system call in a later kernel included), decided by the table being an allow-list of names in `needs.MAPPED_CALLS`, not by a list of exclusions.

## A.7 Generalisation, and paths that did not exist before

- **Shared code, shared rules.** Each mapped access becomes a `record.Need` (Task R2.2), the type PR 162's `generalise` works on, and the recorder calls `generalise.per_run_grants`, `generalise.grants_for`, `generalise.compact` and `generalise.normalise_hierarchy` with `DEFAULT_FINE_ROOTS`, PR 162's compaction threshold and its per-run table. The two pruners therefore agree by construction, not by a second implementation.
- **Per-run names.** PR 162's clause 2 accepts a component as a per-run name when it is seen to change between runs or is the refusing process's own id. The recorder passes the set of every process and thread id its sessions' traces show (it records the whole process tree), so `/proc/<pid>/...` of any process of the session, the parent reading its child's status included, is a per-run name from a single session; `/proc/self` and `/proc/thread-self` arrive already resolved by `-yy` and are rewritten by PR 162's `rewrite_self` when a path argument is used. Merging sessions (A.12) adds the clause 2 evidence across sessions as PR 162 does across runs.
- **Existed before.** The snapshot lists every path outside `/proc` and `/sys` when the container's first session starts (0.14 to 0.30 s in the spike); a `record.Need` on a path not in it belongs to an object the sessions created, and `grants_for` moves it to the nearest pre-existing ancestor, as PR 162 does for the run's own files. That covers the case the request asks about: **a `[read]` or `[execute]` need on a path that did not exist before the session is never written as that path**, so the parser's refusal of a missing `[read]`/`[execute]` path cannot arise from it. `generate` checks the invariant (every `[read]`/`[execute]` row is in the snapshot) before rendering and fails with the offending rows rather than writing them, and the acceptance gate then confirms it against the real parser. Paths that existed and were deleted by a session (the spike's `old.txt`) are in the snapshot and exist again in a fresh container.
- **Created files with a stable name**, such as `/root/.python_history`, follow the same rule: `[create]` and `[write]` on the nearest pre-existing ancestor. That is wider than the one file (A.13), and the alternative of naming the file in `[write]` so that the filesystem layer creates it empty before the run was rejected (A.18): it changes what the program sees at start (a lock file that exists means "locked"), and it would make the two pruners disagree.
- **Directory listings (decision 13).** Listing a directory needs `READ_DIR` on it, which Phobos only grants together with `READ_FILE` through `[read]`, and Markus decided against a list-only section. So the recorder grants `[read]` on a directory a session listed, also inside a fine-grained root, where that makes every file beneath the directory readable although the session read none of them. That is the one place where a fine-grained root is not file by file, and each such entry says so in a comment `cfgfile.render` writes above it, for example `# listed by the session: [read] on a directory also makes every file beneath /etc/ssl/certs readable; Phobos has no list-only right`. `record.json` lists these entries among the widenings with the number of files beneath each.
- **Canonical paths, wildcards, hierarchy.** As PR 162: realpath of the object (from `-yy`), a path holding `*`, `?`, `[` or a newline goes to its parent and is listed, a nested strict subset is raised to its ancestor's rights. The recorder widens PR 162's newline rule to every control character (bytes below 0x20 and 0x7f) and to bytes that are not valid UTF-8, since a carriage return in a path line silently loses the grant (AGENTS.md) and a policy is a text file.
- **Observed text is untrusted.** Paths, host names, DNS answers and TLS host names come from the program and from the network, so nothing observed is written into `policy.cfg` unchecked. A path line must pass the rule above. A host name in a rule must match the DNS grammar (`names.valid_hostname`: labels of 1 to 63 letters, digits and hyphens, not starting or ending with a hyphen, at most 253 characters in all, lower-cased, no trailing dot, not an address); one that does not is never a rule, its address is used instead, and the rejected name is listed in `record.json` only. A comment never carries observed text verbatim: `cfgfile.comment_text` writes every byte outside printable ASCII as `\xHH`, so no observed value can end a comment line and become a rule. Unit fixtures cover a ClientHello whose server name holds `\n[write]\n/`, a DNS answer for such a name and a file name with a carriage return, and the resulting policy has no line the parser reads as a section or a rule from them.
- **The working directory.** The recorder runs the program in the tail's `--chdir` (`/var/tmp/testing-dir` in the shipped `TailPhobos.cfg`), read from `${PHOBOS_HOME}/TailPhobos.cfg`, so the paths it records under the exercise directory are the paths grading uses.

## A.8 Network endpoints and names

### A.8.1 What is recorded

From successful calls of `AF_INET` and `AF_INET6` sockets, IPv4-mapped IPv6 addresses written as IPv4, the transport from the socket's `-yy` decoration (`TCP`, `TCPv6`, `UDP`, `UDPv6`):

| Call | Recorded |
| --- | --- |
| `connect` on a stream socket returning `0` | destination, tcp |
| `connect` on a stream socket returning `EINPROGRESS` | destination, tcp, **only when a connection to it is seen to complete**: any later successful call, by any process of the session, on a descriptor whose `-yy` decoration names a connected stream socket with that remote end (`TCP:[local->remote]`), such as `getsockopt(..., SO_ERROR, [0])`, `getpeername`, a send or a receive; otherwise listed as "attempted, never completed" and not granted. Keying completion by the remote end in the decoration, not by process and descriptor number, keeps it right across `fork` and descriptor reuse |
| `connect` on a datagram socket | destination, udp, **only when a datagram was then sent to it** (A.8.4) |
| `sendto`, `sendmsg`, `sendmmsg` naming a destination | destination, udp |
| `write`, `send`, `sendmsg` on a connected datagram socket | the decorated remote end as "sent to" |
| `bind` | a held endpoint (family, transport, port); port 0 means "the kernel chooses", and the port it chose is read from the socket's next decoration or a `getsockname` on that same socket |
| `listen` on a socket the session never bound | an ephemeral bind, and the held endpoint from the listening socket's decoration |
| `accept`, `accept4` | the peer address and the listening port |

Held endpoints are keyed by family, transport and port, and only an explicit `bind` or a `listen` makes one; the local end of a socket that merely connected (its ephemeral source port, which `getsockname` and the decoration also show) is never a held endpoint. A UDP socket bound to port 40000 therefore does not make a TCP connection to `127.0.0.1:40000` look like the session's own server.

### A.8.2 Rules

- **Loopback.** A destination on `127.0.0.0/8` or `::1` whose family, transport and port match an endpoint a process of the session held becomes the loopback wildcard through the shared `network.loopback_wildcard` (`allow 127.0.0.1:*`, `allow [::1]`, both families `allow localhost`, with ` udp` for datagrams), exactly as PR 162 does. A loopback port no process of the session bound becomes an exact rule with a comment that a service outside the session listened there and must exist at grading time too.
- **Bind.** Port 0 or an unbound `listen` gives `allow 0` (` udp` for datagrams); an explicit port gives `allow <port>` (` udp`), with a comment that an explicit UDP port needs Landlock ABI 10.
- **Accept.** A peer outside loopback produces a comment `# [accept] not generated: accept from <peer> on port <p>; choose the public port and write the rule by hand`. An `[accept]` rule needs a networked deployment and a public port the recording cannot know (README, `[accept]`), so it is never generated.
- **External, TCP, with a TLS host name** (A.8.3): `allow <name>:<port>`, with a comment that grading needs `--resolver` and that the egress broker holds the connection to that name. The header then says "this policy needs --resolver". The program's own DNS lookups for such a name produce no rule: the network layer maps the name in `/etc/hosts` for the command (`config_doc.txt`), measured in the spike's networked replay, which made no DNS query.
- **External, TCP, without a TLS host name**: `allow <address>:<port>`, with the name DNS or `/etc/hosts` gave it as a comment. A name rule cannot be used, since the broker routes by TLS host name only; the address may change, which the comment says. The lookups this needs at grading time are then emitted as `allow <resolver>:53 udp`.
- **External, UDP**: `allow <name>:<port> udp` when DNS named the address (the network layer resolves it once before the command starts and maps it in `/etc/hosts`), otherwise `allow <address>:<port> udp`; both with the ABI 10 comment.
- **DNS lookups not needed by any rule above** are written commented out, so the instructor sees them.

### A.8.3 Recovering a name

The syscalls only see addresses. Three sources, in this order of trust, each recorded in `record.json` with the name:

1. **TLS host name (SNI)**, parsed from the first `write`, `send` or `sendto` on a stream socket whose first bytes are a TLS handshake record holding a ClientHello. It is the name the egress broker checks at grading time, so it is the one a name rule must carry. Measured: `allow example.org:443` from Python's `http.client`.
2. **DNS answers**, parsed from `recvfrom` and `recvmsg` on a socket to port 53 (glibc's resolver reads its answers with `recvfrom`; `read` is not traced, so DNS over TCP read with `read` gives no name): the question name and every `A` and `AAAA` answer, so that an address the session then reached maps to the name it asked for (a `CNAME` chain maps to the name asked). DNS over TLS or HTTPS cannot be read and leaves an address only.
3. **`/etc/hosts`**: `snapshot.take` also copies the container's `/etc/hosts` as it was before the first session into `snapshots/<container>.hosts`, and a session that opened `/etc/hosts` has its addresses named from that copy (`names.hosts_file`). A hosts file the session itself changed is not followed.

A name recovered from DNS or `/etc/hosts` is never turned into a name rule for TCP (the broker could not enforce it without TLS), only into a comment beside the address rule.

### A.8.4 Datagram connects that send nothing

glibc's `getaddrinfo` ranks the addresses of a name (RFC 6724) by `connect`ing a datagram socket to each candidate and reading `getsockname`, without sending anything. Under the layers such a connect is refused, and `getaddrinfo` still answers. The recorder therefore grants a datagram destination only when the session sent a datagram to it, and lists the others as "not granted" (measured: two such connects to port 443 for `example.org`, refused at replay, the HTTPS request unaffected).

## A.9 Limits

Off by default. `generate --limits` derives limits with PR 162's `sampler` (run beside the session, `observe.py` making the recorder the subreaper of every process the session leaves behind) and `limits.margins`, so the margins are PR 162's decision 3:

| Key | Derived | Why |
| --- | --- | --- |
| `cpu` | yes, 5x the highest per-process CPU time | `ulimit -t` is per process; idle time at a prompt costs no CPU |
| `nproc`, `nofile`, `fsize_mb` | yes, PR 162's formulas | they measure the program, not the person |
| `mem_mb` | only with `--memory-pinned`, 2x the peak `VmPeak` | as PR 162's decision 4: `ulimit -v` is address space, which follows the host unless the program pins it (for a JVM, its heap), and the flag is the instructor's assertion that it does; the recorder knows no language |
| `timeout` | only when every merged session ran with standard input not a terminal, 5x the longest wall clock | the wall clock of an interactive session measures the person at the keyboard; such a policy gets no `timeout` line and the default (600 s) applies, which the policy's header says |

Recording slows a call-heavy program (A.4), and the sampler measures that slowed program, so derived limits err permissive; the record states the overhead factor is unknown per program. Limits are written into the generated (exercise) configuration only, as PR 162 does, since a base limit is a floor for every exercise.

## A.10 Safety

The guarantee is structural, and the checks after it are safeguards against mistakes, not containment and not an attestation of the image.

- **The guarantee: its own entry point, never on the grading path.** `phobos-record` is `var/tmp/helpers/layer_record/phobos-record`, run as the container's entry point. Nothing under `core/` names it; `phobos.sh` has no flag that reaches it; the run-phase image contains neither the helpers nor `strace`. A test greps `core/` for `phobos-record`, `layer_record` and `strace` and checks the run-phase image has no `strace` (Task R3.3). A grading run cannot reach the recorder because the recorder is not there.
- **Safeguard: it refuses to look like grading.** `record` refuses `--config`/`-c`, `--resolver` and every `phobos.sh` layer switch with "phobos-record records a program with no sandbox at all; it does not grade. Grade with phobos.sh --config <file>." (status 2). It refuses a command any of whose arguments resolves to a file under `${PHOBOS_HOME}` (which also catches `sh ${PHOBOS_HOME}/phobos.sh`); a wrapper script or `bash -c` that starts the layers is not caught, and the safeguard does not claim to.
- **Safeguard: it refuses to run outside the prune image** (status 3): `${PHOBOS_HOME}/BasePrune.cfg` must exist and no other `Base*.cfg` beside it, which is the shape of PR 162's prune image (Task 3.1 there). That catches starting it in the run-phase image by mistake; it proves nothing about an image built to look the same. It also refuses to run when it is itself traced (`TracerPid` not 0), which would make the session's own tracer fail to attach.
- **It says what it is.** `--help` begins with: "Records the reference program of an exercise. While it records, the program runs with no sandbox at all: the recorder grants everything and only watches. Record the instructor's reference program, never an untrusted submission." The generated file begins:

```
# Recorded by phobos-record, not pruned. Sessions merged: 3 (2026-10-05, 2026-10-06).
# It grants what those sessions exercised and nothing else: a code path no session took,
# a file no session opened in a fine-grained root, a host no session reached, is denied
# at grading time. Review record.json, which lists every widening.
# Recorded from the reference program; never record an untrusted submission.
# This policy needs --resolver (a [connect] rule names a host).
# Limits: none derived (an interactive session's wall clock measures the person).
```

- **Privileges.** None: an ordinary container, `strace` tracing its own descendants (`ptrace_scope` at most 1, which PR 162's `--assert-ptrace` probe checks on the runners), no `--privileged`, `--cap-add` or `--security-opt`. The offline compose service runs `network_mode: none`; the networked one is opt-in and named so.

## A.11 Language independence

Nothing in `layer_record/` knows a language. The fine-grained roots and the per-run table are Linux's, the mapping is Landlock's, the names come from the network. What is language specific stays with the exercise: the program and the files it needs in the exercise directory, a pinned heap asserted with `--memory-pinned` (A.9), a Gradle exercise's settings that keep the build in the launching JVM without a daemon (PR 162's decision 8, its A.6.8) in its own `gradle.properties` and `gradlew`. A recording of a Java tool and of a Python REPL go through the same code, and the spike's REPL session is Python only because the image had it at hand.

## A.12 Merging sessions, and comparing with a policy

- **Merge.** `generate` reads every session of a recording directory; sessions recorded in different containers each carry their own snapshot, and "existed before" is judged per session against its own. The needs of all sessions are unioned before generalisation, so per-run names and compaction see every session at once, and the result is the union of what any session needed. Sessions from different images are refused (the image id is in `session.json`), since their paths describe different filesystems.
- **Diff.** `diff --policy <cfg>` reads the policy with the shared `cfgfile.read_policy` (Task R2.3) and reports two lists, and changes nothing:
  - **needed but not granted**: every mapped need (before generalisation) whose rights are not covered by the policy's rules along its path (Landlock's union over ancestors, both spellings of a symbolic link folded as `fold_table_by_target` does), and every endpoint no `[connect]`/`[bind]` rule admits;
  - **granted but unused**: every policy row and section no need of any session touched at or beneath that path, and every network rule no endpoint matched. This is the input for tightening a shipped base such as `BaseLanguage-java.cfg`; deleting an entry an ancestor covers is still governed by AGENTS.md ("A base entry an ancestor already covers is not dead code"), so `diff` marks such rows "covered by an ancestor; removing it changes which exercise configurations are accepted".

## A.13 Which direction each heuristic errs in

| Heuristic | Errs | Why that direction |
| --- | --- | --- |
| Granting only what succeeded while recording | restrictive | a path no session took is denied at grading; the header says so |
| Directory instead of file for `[read]`/`[execute]` outside fine-grained roots, compaction | permissive (siblings, read-class only) | PR 162's rule, shared |
| Per-run names on their smallest stable directory | permissive (every entry of `/proc` or `/dev/pts` the uid may open) | PR 162's rule, shared; commented in the policy |
| Nearest pre-existing ancestor for created objects, stable names included | permissive (write to existing siblings) | temporary names differ per run; materialising a stable name would change what the program sees |
| Source parent given the destination's sections on a move | permissive on the source | Landlock refuses the move otherwise |
| `[read]` on a listed directory in a fine-grained root | permissive (all files beneath) | Phobos has no list-only right, and none is added (decision 13); each such entry carries a comment |
| Datagram connects that sent nothing not granted | restrictive | glibc's ranking copes with a refusal (measured) |
| A non-blocking connect granted only when seen to complete | restrictive | a connection that failed while recording was handled by the program without the network |
| A host name that fails the DNS grammar is never a rule | restrictive (the address is held instead) | observed text must not shape the policy's syntax |
| Unmapped successful calls make the result incomplete, not ignored | neutral, made visible | the replay check decides whether they matter |
| TLS host name over DNS name over address | restrictive within the name | the broker enforces the TLS name; an address may move |
| An exact loopback rule for a port no process of the session bound | restrictive | the service must exist at grading; reported |
| Limits measured under the tracer | permissive | the traced program is slower than the graded one |
| No `timeout` from an interactive session | neutral, the default applies | a person's typing is not the program's run time |

## A.14 The acceptance criterion: replay with no denial, and both directions

- **Replay.** `phobos-record check -- <command>` runs by default in a fresh container from the same image. A tool inside a container cannot start one, so the fresh container is the caller's: `docker compose --profile record run --rm record check ...` creates a new container for every invocation, and that is the documented way to run it. `check` does not take freshness on trust; it verifies it against a **starting-state fingerprint**. The snapshot records, beside each path and its type, the regular file's size, mode and modification time in nanoseconds, a symbolic link's target, and a directory's mode (not its modification time, which the exercise copy itself changes). After copying the exercise afresh (with its files' times kept, as `shutil.copytree` does) and before the replay, `check` takes the same fingerprint of the container, with the same exclusions: `/proc`, `/sys`, the recordings directory, per-run names, and the files Docker writes into every container itself (`/etc/hostname`, `/etc/hosts`, `/etc/resolv.conf`, `/.dockerenv`, created anew with a new time in each container, and `/dev/console`, present only with `-t`; measured over the 24 516 paths of the spike image, nothing else differed between fresh containers started with and without a terminal). It compares that fingerprint with the one of the recording's first session:
  - an equal fingerprint, in a container no session of the recording ran in: mode `fresh-container`, meaning exactly that the container's starting state matches the recording's as far as the fingerprint sees. A change that keeps a file's size and modification time (a tool can replace a file and preserve its times) is not detected; the recorder serves the instructor's own reference program, and the fingerprint guards against leftovers, not against an adversary;
  - the recording's own container (its id is in `session.json`), or a container whose fingerprint differs (a path added, removed, or changed in type, size, mode, time or target): refused with status 3, naming the container or up to 20 differing paths with what differs, unless `--same-container` is given, the explicit opt-in of decision 12. With it the replay runs in mode `same-container` (the recording's own container) or `changed-container` (another container whose starting state differs), and `check` prints before and after the replay `Warning: this check does not run in a fresh container. Files the recording or an earlier run left behind can make it pass where a fresh container would fail.`

  The summary line and `check-<n>/check.json` record the mode, so a pass is never reported without saying which it was. It copies the exercise afresh, writes an overlay configuration `[limits]` `timeout=0` (GNU timeout puts the command in a process group of its own, which is never the terminal's foreground group, so an interactive command would be stopped by `SIGTTIN` on its first read; measured), and runs `strace -DDD -f ... phobos.sh [--resolver <r>] --config policy.cfg --config <overlay> -- <command>` with the prune image's empty base. With `--script` the session is typed from the file; without it the person repeats the session. The overlay is never written into `policy.cfg`.
- **What counts as a regression: an access signature, not a call name.** The replay's refusals are found with PR 162's `attribute.denials` (the in-domain process tree, errno filtering, and its layer classification). Each refused call is then turned into its **object-specific** pairs by this plan's own mapping (A.6.1 and A.6.3, `needs.pairs_of_call`), applied as if the call had succeeded: a cross-directory rename gives `(source parent, delete)`, `(source parent, restructure)`, `(destination parent, create)` and `(destination parent, restructure)`, never the product of both parents with every section; a network refusal gives the endpoint with its transport; a fixed operation gives its own pair (`("unix:/var/run/nscd/socket", "connect")`, `("setsid", "call")`). The recording's successful calls become pairs through the same function before any generalisation, so both sides are spelt alike. Each refusal is then exactly one of:
  - a **regression**, when any of its pairs was needed by a call that succeeded in some recorded session, whatever layer refused it. A fixed refusal of an operation that succeeded while recording (a UNIX connect that worked bare and is refused by the guard) is a regression too: the program as recorded cannot run under the grading layers, and `check` says so in those words;
  - **harmless fixed**, when PR 162 classifies it `fixed` and no recorded session performed it successfully (the spike's `nscd` connects, which failed while recording too);
  - **new behaviour**, otherwise: the replay did something no recorded session did, such as a write refused on a file the recording only read. It is listed, never folded into "harmless"; when it changes what the program does, the completion rules below fail the check.

  `check` fails on any regression.
- **The replay must have run the session, or the check fails.** No refusal is not enough. `check` fails (status 1) when: Phobos stopped the run itself (PR 162's rule: status `2`, `11`, `15` or `125` together with Phobos's own marker before the command started); the trace shows no in-domain `execve` of the command; a scripted `expect` was not met (`pty_script.EXPECT_FAILED`); or the command's exit status differs from every recorded session's status for the same script. For a session the person repeats by hand, `check` prints the recorded and the replayed status and the number of in-domain calls of each, so a replay that stopped early is visible, and says that only a scripted check is a proof.
- **What it does not compare.** Output equivalence is not checked: `check` judges what the program was allowed to do, not what it printed (see A.19 for the two layer behaviours the spike found).
- **Forbidden direction.** The integration suites run PR 162's containment checks (`probe.c` under the generated policy): a canary file in a fine-grained root and one outside every recorded directory refused for read, a write into a `[read]`-only directory refused, `connect 10.0.0.1:80` and `bind 8080` refused unless recorded.
- **Where.** Every suite runs in an ordinary container, offline unless it is the networked suite, which uses a Docker network with no route out (A.15).

## A.15 Tests

- **Unit (pytest, `tests/python/test_layer_record_*.py`)**: the mapping table of A.6.1 row by row from strace lines (both directions: the call that needs a section and the neighbouring one that does not, such as `O_PATH`, `stat`, a failed open), `openat2` with resolve flags, `fexecve`, `RENAME_EXCHANGE`, and the unsupported calls of A.6.4 making `generate` say incomplete; `execve` granting `[read]` and `[execute]` on the binary and its ELF interpreter and `#!` chain (fixture files in `tmp_path`); A.6.2's source-covers-destination; created objects to the nearest pre-existing ancestor and the invariant that no `[read]`/`[execute]` row is missing from the snapshot; the per-run table with session ids; the network rules of A.8.2 (loopback wildcard, unbound loopback port, the same port held over UDP and connected over TCP, a client socket's own port, a non-blocking connect completed and not, unsent datagram connect, mapped IPv6, bind and listen, accept comment); `names.dns_answers` on captured responses (A, AAAA, CNAME chain, compression, truncated); `names.client_hello_server_name` on captured ClientHellos (TLS 1.2, 1.3, no SNI, truncated); observed text as untrusted (an injected server name, a carriage return in a path, a comment that cannot end its line); the replay check's access signatures and completion rules; the safety refusals of A.10; `diff`'s two lists; limits keys by interactivity and `--memory-pinned`.
- **Integration (shell, in the prune image, ordinary container)**:
  - `tests/integration/record_offline.sh` (`--network none`): a scripted session over a fixture program that reads, writes, creates with random names, deletes, moves across directories, runs a child and a `#!` script, starts a loopback TCP server and UDP pair; `generate`; `check` in a second container with zero refusals; the containment checks; a second session that does something else, merged, both sessions replaying under the merged policy; `diff` against `BaseLanguage-java.cfg` listing at least one needed-but-missing and one unused row from known fixture behaviour.
  - `tests/integration/record_interactive.sh`: `bash -i` in a pseudo-terminal, Ctrl+C, Ctrl+Z and `fg` under `record`, the exit status passed through, a child that outlives the program still recorded (the subreaper waits for the tracer).
  - `tests/integration/record_networked.sh`: a user-defined Docker network created with `--internal` (no route out), a second ordinary container on it serving TLS for `api.phobos.test` with a self-signed certificate and answering DNS for that name; the session connects by name; `generate` writes `allow api.phobos.test:443`; `check` with `--resolver <that container>` replays with zero refusals; a connection to an unrecorded port on the same host is refused.
  - `tests/integration/record_safety.sh`: `record --config x.cfg`, `record -- ${PHOBOS_HOME}/phobos.sh`, `record` in the run-phase image (no `BasePrune.cfg`), each refused with its status and message; `grep -r` over `core/` for the recorder's names finds nothing.

## A.16 CI

- `test.yml`, job `python`: picks up `tests/python/test_layer_record_*.py` with no change.
- `build.yml`, job `run-phase`: after PR 162's prune image is built, run the four record suites in it, the networked one creating its internal network and server container inside the job. Native runners on both architectures.
- `lint.yml`: no new tool; `ruff` and `bandit` reach `var/tmp/helpers/layer_record/` through `var/tmp/helpers`, `shellcheck` the entry script and the suites, `yamllint` the compose change.

## A.17 Risks

| Risk | Consequence | Mitigation |
| --- | --- | --- |
| A program that uses ptrace itself (a debugger, a sanitiser, some profilers) | it fails under the recorder, though grading would allow tracing inside the domain | listed in `--help`; the recording of such a program is incomplete, `check` shows what is missing |
| A call-heavy program records slowly (17x to 19x for 5000 small reads) | long recordings | `--seccomp-bpf` always; interactive use is unaffected (A.4) |
| A session that misses a code path | grading denies it | merge more sessions; the header says so; `check` only proves the recorded paths |
| A session in a container that already ran another program | the snapshot no longer equals the image's state | the snapshot is taken once per container, before its first session; `check` refuses the recording container |
| `strace` output differs between versions | misparsed calls | PR 162's golden fixtures, extended with successful calls and `-yy` lines (R2.1); version in `session.json` |
| A program whose name resolution bypasses DNS on port 53 (DNS over HTTPS) | address rules only | comments name the address; a TLS connection still gives the name |
| An instructor records an untrusted program | it ran unconfined in the recording container | `--help`, the header and the README say never to; the container is ordinary and offline by default, which is the only containment there is |
| The recorder is mistaken for grading | a policy that grants nothing to the reference's untaken paths is shipped unreviewed | the header, `record.json`'s widening list, and the refusal of grading flags |

## A.18 Decisions and rejected alternatives

| # | Decision | Rejected alternative, and why |
| --- | --- | --- |
| 1 | `strace`, shared with PR 162 (A.3.1) | PR 166's report-only supervisor: no results, no output buffers, and a record mode in the grading chain (A.3.2). A dedicated tracer: more C, a second parser. |
| 2 | `-DDD`, the tracer detached (A.3.3) | `strace` as the parent: also measured working, but the tracer would receive terminal signals and own the exit status |
| 3 | A pre-session snapshot of every path to decide "existed before" | inferring creation from the trace alone: `open(O_CREAT)` without `O_EXCL` does not say whether it created; birth times (`statx`): not on every filesystem and not in Python's standard `os.stat` |
| 4 | PR 162's generalisation code, extended to `Need` (A.7) | a recorder-specific generalisation: the two pruners would drift |
| 5 | Created files with stable names on the nearest pre-existing ancestor | naming the file in `[write]` so the filesystem layer creates it empty: changes the program's starting state, and the pruners would disagree |
| 6 | Names from the TLS host name, then DNS, then `/etc/hosts`; name rules for TCP only with TLS (A.8.3) | reverse DNS: a CDN's reverse name is not the name the program meant; name rules from DNS for TCP: the broker cannot enforce them |
| 7 | Datagram connects count only with a send (A.8.4) | granting every datagram connect: grants glibc's ranking probes to every address of a name |
| 8 | Prune image only (A.5.4) | a developer's host: records another filesystem than the graded one |
| 9 | Replay check in a fresh container, interactive by default, scripted with `--script` (A.14) | recording the keystrokes through a pseudo-terminal proxy: changes the terminal the program sees during recording and replays timing-dependent input blindly |
| 10 | `[accept]` as a comment only (A.8.2) | generating `expose ... to ... from`: the public port and the deployment are the instructor's choice |
| 11 | Limits opt-in, no `timeout` from interactive sessions (A.9) | always deriving all limits: a person's pauses would set the timeout |

## A.19 Findings in the grading layers, handled elsewhere

The spike found two behaviours of the grading layers: Ctrl+C under `phobos.sh` kills the relay of the command's standard error (F1), and with a `[connect]` name rule present a loopback connection whose server speaks first waits about 5 s in the egress broker (F2). Each is fixed by a pull request of its own against `core/`, outside this plan (Markus's decision 14, A.20). This plan neither depends on nor tests either.

## A.20 Markus's decisions on this plan's questions

Markus answered the three questions of the first draft on 2026-10-05:

| # | Question | Decision | Rejected alternative, and why |
| --- | --- | --- | --- |
| 12 | May `check` run in the recording's own container? | Yes, as an explicit opt-in, `--same-container`. The default stays a fresh container, which `check` verifies against the recording's snapshot rather than assumes; a container that is not fresh (the recording's own, or one whose starting state differs) needs the opt-in, prints a warning that files left behind can make the check pass where a fresh container would fail, and its output and `check.json` record which mode it ran in (A.14). | Only ever fresh: no way to check where a second container is not at hand. A same-container default: a pass could rest on the recording's own leftovers. |
| 13 | Listing a directory in a fine-grained root | Stay with `[read]`: no list-only section, no sandbox change. The recorder grants `[read]` on a listed directory in a fine-grained root, which makes every file beneath it readable, and says so in a comment above each such entry (A.7). | A list-only section: a change to the sandbox for one access pattern. |
| 14 | F1 and F2 | Each gets its own pull request against `core/`, handled separately; this plan only refers to them (A.19). | Fixing them here: outside this plan's scope, which changes nothing under `core/`. |

## A.21 Review record

Recorded in Part C.

---

# Part B: Pull requests and tasks

Every pull request is based on `main` after its predecessor merged, or stacked on it, in which case `build.yml`, `lint.yml`, `test.yml` and `codeql.yml` are started with `workflow_dispatch` on its branch and linked (AGENTS.md). Every body follows `.github/PULL_REQUEST_TEMPLATE.md` and passes `PR_BODY="$(cat body.md)" java .github/scripts/CheckPullRequestTemplate.java`. Every pull request ends with the full lint set of CLAUDE.md.

| PR | Branch | Content | Needs | Grading behaviour changed |
| --- | --- | --- | --- | --- |
| R1 | `feature/recording-pruner-plan` | this plan and its spike | | no |
| R3a | `feature/record-guard-and-snapshot` | the parts of R3 and R4.3 that need nothing from PR 162: the safety refusals (`guard`), the snapshot and its fingerprint (`snapshot.take`, `snapshot.fingerprint`, `snapshot.read_listing`), scripted sessions (`pty_script`), and `check.mode` with its warning | | no |
| R5a | `feature/record-names` | Task R5.1: host names from TLS client hellos, DNS answers and the hosts file | | no |
| RA | `feature/record-observer` | everything PR 162's PR 3 already allows: Task R2.1, `record.Need` of Task R2.2, `phobos-record record` and `check` (Tasks R3.1, R3.3), the mapping of Task R4.1, the comparison and completion rules and the replay of Task R4.3, the safety, interactive and replay suites | PR 162's PR 3 (merged) | no |
| RB | `feature/record-generate` | Task R2.2's generalisation over `Need`, Task R2.3, `generate` (Task R4.2), the offline suite of Task R4.3, merging and `diff` (Tasks R6.1, R6.2) | RA, and PR 162's PR with `cfgfile` and `generalise` | no |
| RC | `feature/record-network-and-limits` | endpoints to rules and the networked suite (Tasks R5.2, R5.3), optional limits (Task R7.1), the documentation (Task R8.1) | RB, and PR 162's `network` and `limits` | no |

**Who introduces the shared modules, and in which order.** PR 162 introduces `var/tmp/helpers/layer_prune/` (`strace_parse` and `record` in its PR 3, `generalise` and `cfgfile` in its PR 5, `network` in its PR 6, `sampler` and `limits` in its PR 7) and this plan only extends them, in R2, without changing any behaviour PR 162's tests pin. R2 therefore waits for PR 162's PR 6. If PR 162's PR 5 is still open when R2 starts, R2 stacks on it rather than copying a module. Nothing in PR 162 waits for this plan; its parser gains two test cases from this spike (A.4, defect 3), which R2 adds and which PR 162 may take earlier.

**Work that does not wait for PR 162.** R3a and R5a hold the modules of R3, R4.3 and R5.1 that import nothing from `layer_prune`, so they are based on `main` and can merge while PR 162 is still under way. They change nothing a run uses: no entry point reaches them until R3 adds `phobos-record`. R3a delivers Task R3.1's `guard.py` and `snapshot.py` without `snapshot.load` (which returns PR 162's `generalise.Snapshot` and so stays in R3), Task R3.2 whole, and Task R4.3's `check.mode` and `check.NOT_FRESH_WARNING` in a `check.py` that R4.3 then completes. Because `check.mode` must read a written snapshot without PR 162's type, R3a adds `snapshot.read_listing(path: pathlib.Path) -> dict[str, str]`, the listing as `take` wrote it (path to fingerprint), and fixes the two keys of `session.json` that `check.mode` reads and `observe.record_session` (R3) writes: `container_id`, the container's id, and `snapshot`, the snapshot's path relative to the recording directory. R5a is Task R5.1 unchanged. The tests of each task move with the code they test.

**Three pull requests for the rest (Markus, 2026-10-06).** R3a and R5a are merged. Everything else is grouped into RA, RB and RC above, in that order, instead of R2 to R8: RA holds what PR 162's PR 3 (`record`, `strace_parse`, `attribute`) already allows, RB and RC are stacked on the PR of PR 162 that brings `cfgfile`, `generalise`, `network` and `limits`. Where RA's implementation departs from the tasks below, the code says so and this list records why:

- `strace_parse` had already made `split_arguments`, `argument` and `descriptor_path` public, read `->` and `=>` as text and named `KEPT_SUCCESSES` (with `chdir` and `fchdir`); RA extends it with `iter_calls`, `Syscall.decoration` and `RECORD_ARGUMENTS` only. `RECORD_ARGUMENTS` includes `-DDD`, so `observe` adds nothing to it.
- `-qq` suppresses strace's `+++ exited with` lines, so the tests that wanted one look for the call `exit_group(<status>)` instead.
- `attribute.refusals(trace, workdir)` answers each Denial with its refused call and its thread's working directory; `denials` is built on it. The replay check needs the call to compute its pairs.
- Until RB settles how `generalise.Snapshot` serves the recorder, the mapping takes any object with `existed(path)`, and `snapshot.existing(path)` reads a listing into one (`snapshot.Existing`); the kernel trees, the recordings directory and per-run names count as existing. The mapping also remembers what the session created and removed, so a rename onto a name the session created earlier needs `[delete]` there.
- `pty_script.drive` answers `Outcome(status, expectations_met)`, because a command may itself end with 4, the value of `EXPECT_FAILED`; `run` keeps its contract. `check.completed` therefore takes every call of the replay and `expectations_met: bool | None` instead of `script_status`, and `session.json` records `script_sha256` and `expectations_met`, which decide the recorded statuses a scripted replay is held to.
- The replay runs strace with `check.REPLAY_ARGUMENTS`: `-DDD -f -qq -yy -x -s 4096` and the recorder's trace set plus `landlock_restrict_self`, `ftruncate` and `getdents64`, without `--seccomp-bpf`, which would hide the calls the connect guard decides.
- The stop rule of PR 162's A.6.4 (status 2, 11, 15 or 125 with Phobos's own marker, before the command started) is not a function of PR 162 yet, so `check.completed` states it; it moves to PR 162's helper once one exists.
- The run-phase image has no `python3`, so the `phobos-record` script itself answers status 3 there instead of `command not found`.
- `guard.refuse_grading_options` takes the options a subcommand accepts on purpose: `check` takes `--resolver` for `phobos.sh`.
- Network pairs are read in RA as far as the replay comparison needs them (destination and transport of a connection or datagram, a held port, a datagram connect counting only with a send); a non-blocking connect counts there only when it returned 0, and its completion rule of A.8.1 arrives with the rules in RC.
- The replay is proven in RA with hand-written policies (`tests/integration/record-fixture/`) and a narrowed one, in `tests/integration/record_replay.sh`, one phase per new container, started by `tests/integration/record_host.sh`, which also checks the run-phase image from outside. Its phase `hand` is Task R4.3 step 6: keystrokes typed into an interactive bash run `check` by hand around `python3 -q`, with Ctrl+C, Ctrl+Z and fg under the layers; a modified existing file (container D) is a phase of its own. RB adds `record_offline.sh` with a generated policy.
- From RA's review: a creation, removal, rename or link acts on the name, so only the directory part is resolved and a symbolic link in the last component is never followed; `/proc/self`, `/proc/thread-self`, `/dev/fd` and the standard streams are written out for the calling thread, never resolved in the analysing process; an open whose decoration names no path (a pipe through `/dev/stdin`) needs nothing; pairs spell a process's `/proc` entry and a pseudo-terminal as placeholders (`needs.comparable`), so the check compares them across runs; a device ioctl is judged by the descriptor's own decoration, and `RECORD_ARGUMENTS` traces `dup`, `dup2`, `dup3` and `fcntl` to follow a device the session opened, and `open_by_handle_at`, which `%file` does not include; renaming or removing a directory removes every name beneath it for the mapping; a non-blocking connect that answered EINPROGRESS counts in the replay's comparison (never as a grant).
- Two calls glibc makes on its own, the AF_UNSPEC connect that resets its ranking datagram socket and the raw netlink route socket of its address check, are refused by the connect guard and tolerated by glibc. RA lists them as `tolerated` rather than fixed refusals, as A.8.4 does for the ranking connects, so a replay does not fail on them; a program that needs netlink itself then shows only through its outcome. This is a choice for Markus to confirm.
- A UNIX connect is a fixed refusal whatever socket it reaches, the session's own included, because the connect guard refuses the family (A.6.1); A.6.3's "outside the session" is read as describing the usual case, not an exception.
- A session leaves no process running: after the command ends the recorder waits `observe.LINGER_SECONDS` (10 s), then names and stops what is left (SIGTERM, then SIGKILL), so a daemon cannot keep the trace open; `session.json` and `check.json` list what was stopped. Ctrl+C is caught for the whole run, and a command a signal ended on the person's terminal ends the recorder by the same signal.
- `check` holds a replay to the recorded sessions of the same command whose script, if any, was met, and of those to the ones typed from the same script; a replay of another command, or of a script no session was typed from, does not count as running the session. It refuses the recording's own container before it copies anything.
- `Denial.need()` of Task R2.2 moves to RB, where generalisation consumes it.

## PR R2: Shared groundwork

### Task R2.1: Every completed call from the parser

**Files:**
- Modify: `var/tmp/helpers/layer_prune/strace_parse.py`
- Modify: `tests/python/test_layer_prune_strace_parse.py`
- Create: `tests/python/fixtures/strace/record.txt` (golden lines captured with the recorder's options from the prune image)

**Interfaces:**
- Consumes: `record.Syscall`, `strace_parse.parse_line`, `strace_parse.parse_trace` (PR 162, Task 3.2).
- Produces:
  - `strace_parse.iter_calls(lines: Iterable[str]) -> Iterator[Syscall]`, every completed call in log order, successful or not, unfinished halves joined; `parse_trace` is rebuilt on it and keeps its contract.
  - `record.Syscall` gains `decoration: str` (the `-y`/`-yy` text after the result, `""` when none), default `""` so PR 162's constructors keep working.
  - `strace_parse.RECORD_ARGUMENTS: tuple[str, ...]`, the recorder's options (A.3.1, A.3.4), beside `STRACE_ARGUMENTS`.
  - `strace_parse.split_arguments(text: str) -> list[str]`, the top-level split `path_argument` already does inside, made public so the recorder reads socket addresses and buffers through the same code.
  - `strace_parse.KEPT_SUCCESSES: frozenset[str]`, the successful calls `parse_trace` keeps (PR 162, Task 3.2 Interfaces), named once.

- [ ] **Step 1: Capture golden lines.** In the prune image: `strace -DDD -f -qq -yy -x -s 4096 --seccomp-bpf -e trace=%file,%network,%process,ioctl,fchdir,write,setsid,setpgid,io_uring_setup -o /tmp/r.txt -- python3 -c 'import socket,os; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); c=socket.create_connection(s.getsockname()); open("/etc/hostname").read(); os.rename("/tmp/a","/tmp/b") if os.path.exists("/tmp/a") else None'` after `touch /tmp/a`, and keep a successful `openat` with a decorated result, a `getsockname` with `[128 => 16]`, a `connect` on a decorated socket with `->`, a `write` on a TCP socket, a `renameat2`, an `execve`, `clone3` lines, and a call interrupted by another process's line. Record the strace version in the existing `VERSION` file.
- [ ] **Step 2: Write the failing tests.**

```python
def test_iter_calls_keeps_successful_calls_and_their_decoration():
    line = '16 openat(AT_FDCWD</w>, "/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</usr/lib/libc.so.6>'
    [call] = list(strace_parse.iter_calls([line]))
    assert call.result == 3
    assert call.errno is None
    assert call.decoration == "</usr/lib/libc.so.6>"


def test_an_arrow_in_a_socket_decoration_does_not_close_a_bracket():
    line = '16 write(3<TCP:[172.17.0.2:32972->172.66.157.237:443]>, "\\x16\\x03\\x01", 3) = 3'
    [call] = list(strace_parse.iter_calls([line]))
    assert strace_parse.split_arguments(call.arguments) == [
        "3<TCP:[172.17.0.2:32972->172.66.157.237:443]>", '"\\x16\\x03\\x01"', "3"]


def test_an_in_out_length_does_not_close_a_bracket():
    line = '16 getsockname(3<TCP:[127.0.0.1:4]>, {sa_family=AF_INET, sin_port=htons(4), sin_addr=inet_addr("127.0.0.1")}, [128 => 16]) = 0'
    [call] = list(strace_parse.iter_calls([line]))
    assert len(strace_parse.split_arguments(call.arguments)) == 3


def test_parse_trace_still_drops_the_successes_it_never_kept():
    lines = [
        '16 openat(AT_FDCWD</w>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>',
        '16 openat(AT_FDCWD</w>, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)',
    ]
    kept = strace_parse.parse_trace(lines).syscalls
    assert [call.errno for call in kept] == ["EACCES"]
    assert all(call.errno or call.name in strace_parse.KEPT_SUCCESSES for call in kept)


def test_every_golden_record_line_parses_or_is_a_known_non_call():
    for raw in (FIXTURES / "record.txt").read_text().splitlines():
        assert strace_parse.parse_line(raw) is not None or strace_parse.is_non_call(raw), raw
```

If PR 162 did not name `KEPT_SUCCESSES` as a constant, it is added in this task with exactly the members its Task 3.2 lists, so the test states the contract rather than repeating it, and PR 162's own parser tests must pass unchanged.

- [ ] **Step 3: Run them to see them fail**: `python3 -m pytest tests/python/test_layer_prune_strace_parse.py -q`. Expected: `AttributeError: module 'layer_prune.strace_parse' has no attribute 'iter_calls'` and the two bracket cases failing.
- [ ] **Step 4: Implement.** `iter_calls` holds what `parse_trace` did line by line; `parse_trace` filters it. In `split_arguments`, a `>` whose previous character is `-` or `=` is text, not a closing bracket.
- [ ] **Step 5: Pass, lint** (`ruff check --no-cache .`, `bandit --recursive --ini .bandit --severity-level medium docker/prune_phase/orchestrate var/tmp/helpers`), **commit** the four paths by name: `Let the strace parser yield every completed call, and read -> and => as text`.

### Task R2.2: `Need`, and per-run names judged against the session's own ids

**Files:**
- Modify: `var/tmp/helpers/layer_prune/record.py`
- Modify: `var/tmp/helpers/layer_prune/generalise.py`
- Modify: `tests/python/test_layer_prune_generalise.py`

**Interfaces:**
- Consumes: `record.Denial(pid, layer, operation, objects, sections, address, port, transport, errno, run, tid)` and `generalise.grants_for`, `generalise.per_run_grants` (PR 162, Tasks 3.3 and 5.1).
- Produces:
  - `record.Need(objects: tuple[str, ...], sections: frozenset[str], run: int, tid: int, tgid: int, evidence: str)`, frozen; `Denial.need() -> Need`.
  - `generalise.grants_for(needs: Iterable[Need], snapshot: Snapshot, fine_roots: tuple[str, ...]) -> dict[str, frozenset[str]]` and `generalise.per_run_grants(needs: Iterable[Need], own_ids: frozenset[int] = frozenset()) -> tuple[dict[str, frozenset[str]], dict[str, str]]`; a `Denial` passed where a `Need` is expected is converted with `need()`, so PR 162's callers are unchanged.

- [ ] **Step 1: Failing tests.**

```python
def test_a_denial_and_a_need_generalise_alike():
    denial = read("/usr/lib/jvm/lib/modules")
    assert generalise.grants_for([denial], snapshot_with("/usr/lib/jvm/lib"), generalise.DEFAULT_FINE_ROOTS) == \
        generalise.grants_for([denial.need()], snapshot_with("/usr/lib/jvm/lib"), generalise.DEFAULT_FINE_ROOTS)


def test_another_process_of_the_session_is_a_per_run_name_from_one_run():
    need = record.Need(objects=("/proc/977/status",), sections=frozenset({"read"}), run=1, tid=300, tgid=300, evidence="openat")
    grants, comments = generalise.per_run_grants([need], own_ids=frozenset({300, 977}))
    assert grants == {"/proc": frozenset({"read"})}
    assert comments["/proc"].startswith("per-run name: /proc/<pid>/status")


def test_a_process_outside_the_session_seen_once_is_granted_file_by_file():
    need = record.Need(objects=("/proc/1/cmdline",), sections=frozenset({"read"}), run=1, tid=300, tgid=300, evidence="openat")
    grants, _ = generalise.per_run_grants([need], own_ids=frozenset({300}))
    assert grants == {}
```

The last test pins the restrictive direction: `per_run_grants` leaves a need it does not take to `grants_for`, which grants `/proc/1/cmdline` file by file.

- [ ] **Step 2: Fail. Step 3: Implement**: clause 2 of PR 162's A.6.5 also accepts a value in `own_ids`. **Step 4: Pass, lint, commit** the three paths: `Generalise needs as well as denials, and know a session's own process ids`.

### Task R2.3: The renderer's header and comments, a policy reader, and the loopback rule

**Files:**
- Modify: `var/tmp/helpers/layer_prune/cfgfile.py`
- Modify: `var/tmp/helpers/layer_prune/network.py`
- Modify: `tests/python/test_layer_prune_cfgfile.py`
- Modify: `tests/python/test_layer_prune_network.py`
- Modify: `tests/integration/layer_prune_observer.sh` (the parser accepts a rendered policy with a header and network comments)

**Interfaces:**
- Consumes: `cfgfile.Policy(fs, connect, bind, limits, comments)`, `cfgfile.render`, `network.network_rules` (PR 162, Tasks 4.2, 5.2, 6.1).
- Produces:
  - `cfgfile.Policy` gains `header: tuple[str, ...] = ()` (written as `# ` lines first) and `notes: tuple[str, ...] = ()` (written as `# ` lines last); `connect` and `bind` entries may be `cfgfile.Rule(text: str, comment: str)`, rendered as the comment line above the rule, and a rule whose text starts with `# ` is written as a comment.
  - `cfgfile.read_policy(text: str) -> Policy`, the inverse of `render` for every section `phobos-policy-parse.sh` knows, comments dropped; PR 162's orchestrator merge (its Task 8.2) uses the same function.
  - `cfgfile.comment_text(text: str) -> str`, every character outside printable ASCII written as `\xHH` (UTF-8 bytes), used for every comment `render` writes; `render` raises `ValueError` for a path or rule holding any control character or non-UTF-8 byte, beside PR 162's existing refusals.
  - `network.loopback_wildcard(families: frozenset[str], transport: str) -> str`, `families` a subset of `{"inet", "inet6"}`, returning `allow 127.0.0.1:*`, `allow [::1]` or `allow localhost`, with ` udp` for `transport == "udp"`; `network.network_rules` uses it.

- [ ] **Step 1: Failing tests.**

```python
def test_a_header_and_rule_comments_are_written_and_read_back_without_them():
    policy = cfgfile.Policy(fs={"/var/tmp/testing-dir": frozenset({"read"})},
                            connect=(cfgfile.Rule("allow example.org:443", "TLS host name"),),
                            bind=("allow 0",), limits={}, comments={},
                            header=("Recorded by phobos-record.",), notes=("Grading will refuse: setsid",))
    text = cfgfile.render(policy)
    assert text.startswith("# Recorded by phobos-record.\n")
    assert "# TLS host name\nallow example.org:443\n" in text
    assert text.rstrip().endswith("# Grading will refuse: setsid")
    again = cfgfile.read_policy(text)
    assert again.connect == ("allow example.org:443",)
    assert again.fs == policy.fs


def test_a_comment_cannot_end_its_line_and_become_a_rule():
    policy = cfgfile.Policy(fs={}, connect=(cfgfile.Rule("allow 127.0.0.1:*", "seen as evil\n[write]\n/"),),
                            bind=(), limits={}, comments={})
    text = cfgfile.render(policy)
    assert "\n[write]\n" not in text
    assert "seen as evil\\x0a[write]\\x0a/" in text


@pytest.mark.parametrize("path", ["/tmp/a\rb", "/tmp/a\x1bb", "/tmp/a\x7fb"])
def test_a_path_with_a_control_character_is_refused(path):
    with pytest.raises(ValueError):
        cfgfile.render(cfgfile.Policy(fs={path: frozenset({"read"})}, connect=(), bind=(), limits={}, comments={}))


def test_both_loopback_families_are_localhost_and_udp_keeps_its_marker():
    assert network.loopback_wildcard(frozenset({"inet", "inet6"}), "tcp") == "allow localhost"
    assert network.loopback_wildcard(frozenset({"inet"}), "udp") == "allow 127.0.0.1:* udp"
```

- [ ] **Step 2: Integration check, failing first**: in `layer_prune_observer.sh`, render a policy with a header, a commented rule and a commented-out rule in Python inside the prune image and pass it to `phobos-policysystem.sh --spec-dir "$(mktemp -d /var/tmp/spec.XXXXXX)" --config <it>`; expect status 0, and status 11 for the same policy with `/usr/bin` in `[read]` beneath `/usr` in `[read]` and `[execute]` (a strict subset), so the check shows the parser and the renderer agree in both directions.
- [ ] **Step 3: Implement. Step 4: Pass, lint, commit** the five paths: `Let generated policies carry a header and comments, and read a policy back`.

## PR R3: The observer and its safety

### Task R3.1: `phobos-record record`

**Files:**
- Create: `var/tmp/helpers/layer_record/__init__.py`
- Create: `var/tmp/helpers/layer_record/phobos-record`
- Create: `var/tmp/helpers/layer_record/main.py`
- Create: `var/tmp/helpers/layer_record/guard.py`
- Create: `var/tmp/helpers/layer_record/observe.py`
- Create: `var/tmp/helpers/layer_record/snapshot.py`
- Create: `tests/python/test_layer_record_guard.py`
- Create: `tests/python/test_layer_record_observe.py`

**Interfaces:**
- Consumes: `strace_parse.RECORD_ARGUMENTS` (R2.1), `generalise.Snapshot` (PR 162, Task 5.1).
- Produces:
  - `guard.refuse_grading_options(arguments: list[str]) -> None`, `guard.refuse_outside_prune_image(phobos_home: pathlib.Path) -> None`, `guard.refuse_layer_command(command: list[str], phobos_home: pathlib.Path) -> None`, `guard.refuse_when_traced(status_text: str) -> None`, each raising `guard.Refused(status: int, message: str)`; `guard.EXIT_USAGE = 2`, `guard.EXIT_ENVIRONMENT = 3`.
  - `snapshot.take(path: pathlib.Path, root: pathlib.Path = pathlib.Path("/"), skip: tuple[str, ...] = ("/proc", "/sys", "/var/tmp/recordings")) -> int`, per-run names (`/dev/pts/<n>`) left out. Each line is `<fingerprint>\t<path>` (path relative to `root` written as absolute), the fingerprint being `f <mode> <size> <mtime_ns>` for a regular file, `l <target>` for a symbolic link, `d <mode>` for a directory and `o <mode>` for anything else; `take` returns the number of paths written and writes a copy of `<root>/etc/hosts` beside it with the suffix `.hosts`.
  - `snapshot.DOCKER_MANAGED = ("/etc/hostname", "/etc/hosts", "/etc/resolv.conf", "/.dockerenv", "/dev/console")`, the files Docker writes into each container (A.14), left out of the fingerprint.
  - `snapshot.fingerprint(root: pathlib.Path = pathlib.Path("/")) -> dict[str, str]`, the same mapping without writing it and without `DOCKER_MANAGED`, so two fresh containers from one image, with the exercise copied the same way, give equal fingerprints; `check.mode` compares it (Task R4.3).
  - `snapshot.load(path: pathlib.Path) -> generalise.Snapshot` reads a written snapshot back for generalisation.
  - `observe.tail_chdir(tail_flags: pathlib.Path) -> pathlib.Path`, the `--chdir` of `TailPhobos.cfg`.
  - `observe.record_session(command: list[str], recording: pathlib.Path, workdir: pathlib.Path, script: pathlib.Path | None) -> observe.SessionResult(number: int, status: int, interactive: bool)`, which makes the process a child subreaper, runs `strace -DDD ... -o <session>/trace -- <command>` in `workdir` with the terminal untouched, waits for the command, then reaps every remaining child (the detached tracer among them) before writing `session.json`.

- [ ] **Step 1: Failing tests.**

```python
def test_a_config_option_is_refused_as_grading():
    with pytest.raises(guard.Refused) as refused:
        guard.refuse_grading_options(["--config", "exercise.cfg", "--", "python3"])
    assert refused.value.status == guard.EXIT_USAGE
    assert "does not grade" in refused.value.message


@pytest.mark.parametrize("option", ["-c", "--resolver", "-nnr", "--no-filesystem-restriction", "-nr"])
def test_every_grading_switch_is_refused(option):
    with pytest.raises(guard.Refused):
        guard.refuse_grading_options([option, "x", "--", "python3"])


def test_arguments_after_the_separator_belong_to_the_command():
    guard.refuse_grading_options(["--", "python3", "--config", "x"])


def test_the_run_phase_image_is_refused(tmp_path):
    (tmp_path / "BaseLanguage-java.cfg").write_text("[read]\n/usr\n")
    with pytest.raises(guard.Refused) as refused:
        guard.refuse_outside_prune_image(tmp_path)
    assert refused.value.status == guard.EXIT_ENVIRONMENT


def test_the_prune_image_is_accepted(tmp_path):
    (tmp_path / "BasePrune.cfg").write_text("# grants nothing\n")
    guard.refuse_outside_prune_image(tmp_path)


def test_the_layers_themselves_cannot_be_recorded(tmp_path):
    (tmp_path / "phobos.sh").write_text("#!/bin/sh\n")
    with pytest.raises(guard.Refused):
        guard.refuse_layer_command([str(tmp_path / "phobos.sh"), "--config", "x"], tmp_path)


def test_the_layers_started_through_an_interpreter_are_refused_too(tmp_path):
    (tmp_path / "phobos.sh").write_text("#!/bin/sh\n")
    with pytest.raises(guard.Refused):
        guard.refuse_layer_command(["sh", str(tmp_path / "phobos.sh"), "--", "true"], tmp_path)


def test_a_program_outside_the_layers_is_accepted(tmp_path):
    guard.refuse_layer_command(["python3", "-q"], tmp_path)


def test_the_snapshot_lists_the_tree_and_keeps_the_hosts_file_beside_it(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "hosts").write_text("192.0.2.7 api.phobos.test\n")
    (root / "proc").mkdir()
    (root / "proc" / "1").mkdir()
    out = tmp_path / "out"
    out.mkdir()
    snapshot.take(out / "c.txt", root=root)
    listing = (out / "c.txt").read_text().splitlines()
    assert any(line.startswith("f ") and line.endswith("\t/etc/hosts") for line in listing)
    assert not any(line.endswith("\t/proc/1") for line in listing)
    assert (out / "c.hosts").read_text() == "192.0.2.7 api.phobos.test\n"


def test_a_traced_recorder_refuses():
    with pytest.raises(guard.Refused):
        guard.refuse_when_traced("Name:\tpython3\nTracerPid:\t42\n")


def test_the_working_directory_is_the_tails(tmp_path):
    tail = tmp_path / "TailPhobos.cfg"
    tail.write_text("# comment\n--chdir /var/tmp/testing-dir\n")
    assert observe.tail_chdir(tail) == pathlib.Path("/var/tmp/testing-dir")


def test_a_recorded_session_keeps_the_commands_status_and_a_complete_trace(tmp_path):
    result = observe.record_session(["sh", "-c", "cat /etc/hostname > /dev/null; exit 7"], tmp_path, tmp_path, None)
    assert result.status == 7
    trace = (tmp_path / "sessions" / str(result.number) / "trace").read_text()
    assert '"/etc/hostname"' in trace
    assert "+++ exited with 7 +++" in trace
```

The last test needs `strace`; it is marked `@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is only in the prune image")`, and the integration suites run it where it is present, so a skip on a developer's machine is never the only run.

- [ ] **Step 2: Fail. Step 3: Implement.** `phobos-record` is bash: `set -euo pipefail`, then `exec python3 "$(dirname "$(readlink -f "$0")")/main.py" "$@"`. `main.py` uses `argparse` with subcommands and an `--help` whose first paragraph is A.10's text verbatim; `record` calls the four guards first, copies the exercise (when `--exercise` names an existing directory, or `/srv/phobos-record-exercise` exists) into the tail's `--chdir` before the container's first session, takes the snapshot under `snapshots/<container id>.txt` (container id from `/proc/self/cgroup` or the host name), then `observe.record_session`. `PR_SET_CHILD_SUBREAPER` is `ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)`, the number named once as a constant with a comment. Every function carries a docstring saying what it does and assumes.
- [ ] **Step 4: Pass, lint, commit** the eight paths: `Record a program under strace with the terminal passed through, and refuse to look like grading`.

### Task R3.2: Scripted sessions

**Files:**
- Create: `var/tmp/helpers/layer_record/pty_script.py`
- Create: `tests/python/test_layer_record_pty_script.py`

**Interfaces:**
- Produces: `pty_script.parse(text: str) -> list[pty_script.Action]` (`Action(kind: str, value: str)`, kinds `send`, `expect`, `key`, `sleep`), `pty_script.run(command: list[str], actions: list[Action], cwd: pathlib.Path, transcript: pathlib.Path, step_seconds: float = 60.0) -> int` (the command's status, or `pty_script.EXPECT_FAILED = 4` when an `expect` timed out); `pty_script.KEYS = {"ctrl-c": "\x03", "ctrl-d": "\x04", "ctrl-z": "\x1a", "ctrl-backslash": "\x1c"}`.

- [ ] **Step 1: Failing tests.**

```python
def test_a_script_is_parsed_line_by_line_and_comments_are_skipped():
    actions = pty_script.parse("# setup\nsend import os\nexpect ^OK\nkey ctrl-c\nsleep 1\n")
    assert [action.kind for action in actions] == ["send", "expect", "key", "sleep"]


def test_an_unknown_action_is_refused():
    with pytest.raises(ValueError, match="line 1"):
        pty_script.parse("type x\n")


def test_a_session_runs_in_a_terminal_and_an_expectation_must_hold(tmp_path):
    actions = pty_script.parse('send import sys; print("OK-" + str(sys.stdin.isatty()))\nexpect OK-True\nsend exit()\n')
    assert pty_script.run([sys.executable, "-q", "-i"], actions, tmp_path, tmp_path / "t.txt") == 0


def test_an_expectation_that_never_holds_fails_the_session(tmp_path):
    actions = pty_script.parse("expect never-printed\n")
    assert pty_script.run(["cat"], actions, tmp_path, tmp_path / "t.txt", step_seconds=1.0) == pty_script.EXPECT_FAILED
```

- [ ] **Step 2: Fail. Step 3: Implement** with `pty.fork`, `select` and a read buffer, as the spike's `drive_session.py` does; a marker must be matched in output after the echo of the typed line, so scripts print markers the echo cannot contain (the spike's `"OK-" + "R1"`). **Step 4: Pass, lint, commit** both paths: `Type a recorded session from a script through a pseudo-terminal`.

### Task R3.3: Compose services and the safety suite

**Files:**
- Modify: `docker-compose.yaml`
- Create: `tests/integration/record_safety.sh`
- Modify: `.github/workflows/build.yml` (run the suite in the prune image)

**Interfaces:**
- Produces: services `record` (offline) and `record_networked`, both under `profiles: ["record"]` so `docker compose up` never starts them.

- [ ] **Step 1: Write the suite first**, sourcing `tests/harness.sh`, with these checks, each `ok`/`bad` with the observed text:

```bash
# record refuses a grading configuration with status 2 and says it does not grade.
check_record_refuses_config() {
  local output
  local status
  output="$(phobos-record record --config /dev/null -- true 2>&1)" && status=0 || status=$?
  if [[ "$status" == 2 && "$output" == *"does not grade"* ]]; then
    ok "record refuses --config"
  else
    bad "record refuses --config" "status ${status}: ${output}"
  fi
}

# record refuses to trace the layers themselves, started directly or through an interpreter.
check_record_refuses_the_layers() {
  local status
  phobos-record record -- "${PHOBOS_HOME}/phobos.sh" -- true > /dev/null 2>&1 && status=0 || status=$?
  if [[ "$status" == 2 ]]; then ok "record refuses phobos.sh"; else bad "record refuses phobos.sh" "status ${status}"; fi
  phobos-record record -- sh "${PHOBOS_HOME}/phobos.sh" -- true > /dev/null 2>&1 && status=0 || status=$?
  if [[ "$status" == 2 ]]; then ok "record refuses sh phobos.sh"; else bad "record refuses sh phobos.sh" "status ${status}"; fi
}

# Nothing under core/ knows the recorder or strace.
check_core_does_not_reach_the_recorder() {
  if grep -rIl -e 'phobos-record' -e 'layer_record' -e 'strace' /repo/core; then
    bad "core/ never names the recorder or strace"
  else
    ok "core/ never names the recorder or strace"
  fi
}
```

and, run from the job rather than the container, `docker run --rm --network none --entrypoint sh <run-phase image> -c 'command -v strace'` must fail (the grading image has no tracer), and `phobos-record` started in the run-phase image with the helpers mounted must end with status 3.

- [ ] **Step 2: Run it before the compose change** in the prune image built by PR 162: `docker run --rm --network none -v "$PWD:/repo:ro" -v "$PWD/var/tmp/helpers:/var/tmp/helpers:ro" --entrypoint bash phobos-prune-layers:local -c 'ln -s /var/tmp/helpers/layer_record/phobos-record /usr/local/bin/phobos-record && bash /repo/tests/integration/record_safety.sh'`. Expected: all passed; it fails only if R3.1 is missing.
- [ ] **Step 3: Add the services**: `build: docker/prune_phase/layers` with `RUN_PHASE_IMAGE`, `entrypoint: ["/var/tmp/helpers/layer_record/phobos-record"]`, `stdin_open: true`, `tty: true`, volumes `./var/tmp/helpers` read-only at `/var/tmp/helpers`, `${RECORD_EXERCISE:-./var/tmp/testing-dir/record-empty}` read-only at `/srv/phobos-record-exercise`, `./var/tmp/recordings` read-write at `/var/tmp/recordings`; `record` with `network_mode: none`; neither with `privileged`, `cap_add` or `security_opt`. `yamllint --strict .`.
- [ ] **Step 4: Wire the suite into `build.yml`** after PR 162's prune-image steps, lint (`shellcheck -x -S warning`, `actionlint`, `yamllint --strict .`, `ec --no-color`), **commit** the three paths: `Offer the recorder as its own compose service, and prove it cannot be mistaken for grading`.

## PR R4: Filesystem needs, generation and the replay check

### Task R4.1: Successful calls to needs

**Files:**
- Create: `var/tmp/helpers/layer_record/needs.py`
- Create: `tests/python/test_layer_record_needs.py`

**Interfaces:**
- Consumes: `strace_parse.iter_calls`, `record.Need`, `generalise.Snapshot`.
- Produces:
  - `needs.SessionNeeds(needs: list[Need], fixed: list[str], unsupported: list[str], moves: set[tuple[str, str]], process_ids: frozenset[int], listed_directories: set[str])`.
  - `needs.MAPPED_CALLS: frozenset[str]`, every call name A.6.1 states an effect for (the "none" rows included); a successful `%file` call outside it, or one of A.6.4's cases, goes to `unsupported` with its trace line.
  - `needs.read_session(calls: Iterable[Syscall], snapshot: Snapshot, workdir: str, run: int) -> SessionNeeds`, the table of A.6.1 and A.6.3; the working directory per process starts at `workdir`, is inherited at `clone`, `clone3`, `fork`, `vfork` and follows `chdir` and `fchdir`.
  - `needs.pairs_of_call(call: Syscall, snapshot: Snapshot, cwd: str) -> set[tuple[str, str]]`, the object-specific pairs of one call as if it had succeeded (A.14): each object with exactly the sections the mapping gives that object, endpoints as `("<address>:<port> <transport>", "connect")` or `("<port> <transport>", "bind")`, a fixed operation as its own pair (`("unix:<path>", "connect")`, `("<call name>", "call")`, `("ioctl <command> <device>", "call")`).
  - `needs.access_pairs(calls: Iterable[Syscall], snapshot: Snapshot, workdir: str) -> set[tuple[str, str]]`, the union of `pairs_of_call` over every successful call of a session, fixed operations included, before any generalisation, which the replay check compares against (Task R4.3).
  - `needs.exec_chain(path: str) -> list[str]`, the binary, its `PT_INTERP` and its `#!` interpreters, each canonical.

- [ ] **Step 1: Failing tests, one per row of A.6.1 and A.6.3, the neighbouring non-grant beside each.** For example:

```python
def test_an_open_for_reading_needs_read_on_the_resolved_file(snapshot):
    result = needs_of('16 openat(AT_FDCWD</w>, "/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</usr/lib/libc.so.6>', snapshot)
    assert sections_on(result, "/usr/lib/libc.so.6") == {"read"}


def test_an_o_path_open_needs_nothing(snapshot):
    result = needs_of('16 openat(AT_FDCWD</w>, "/etc", O_RDONLY|O_PATH|O_DIRECTORY) = 3</etc>', snapshot)
    assert result.needs == []


def test_a_failed_open_needs_nothing(snapshot):
    result = needs_of('16 openat(AT_FDCWD</w>, "/etc/missing", O_RDONLY) = -1 ENOENT (No such file or directory)', snapshot)
    assert result.needs == []


def test_a_stat_needs_nothing(snapshot):
    result = needs_of('16 newfstatat(AT_FDCWD</w>, "/etc/shadow", {st_mode=S_IFREG|0640, st_size=1, ...}, 0) = 0', snapshot)
    assert result.needs == []


def test_creating_a_new_file_needs_create_on_the_parent_and_write_on_the_new_file(snapshot):
    result = needs_of('16 openat(AT_FDCWD</w>, "/w/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</w/out.txt>', snapshot_with("/w"))
    assert sections_on(result, "/w") == {"create"}
    assert sections_on(result, "/w/out.txt") == {"write"}


def test_an_execve_needs_execute_and_read_on_the_binary_and_its_interpreter(tmp_path):
    binary = elf_with_interpreter(tmp_path / "tool", interpreter=str(tmp_path / "ld.so"))
    (tmp_path / "ld.so").write_bytes(b"\x7fELF")
    result = needs_of(f'16 execve("{binary}", ["tool"], 0x0 /* 1 var */) = 0', snapshot_with(str(tmp_path), str(binary), str(tmp_path / "ld.so")))
    assert sections_on(result, str(binary)) == {"execute", "read"}
    assert sections_on(result, str(tmp_path / "ld.so")) == {"execute", "read"}


def test_a_move_across_directories_needs_restructure_on_both_parents_and_is_remembered(snapshot):
    result = needs_of('16 renameat2(AT_FDCWD</w>, "/tmp/a", AT_FDCWD</w>, "/w/b", 0) = 0', snapshot_with("/tmp", "/w", "/tmp/a"))
    assert sections_on(result, "/tmp") == {"delete", "restructure"}
    assert sections_on(result, "/w") == {"create", "restructure"}
    assert result.moves == {("/tmp", "/w")}


def test_a_unix_connect_is_a_fixed_refusal_and_no_grant(snapshot):
    result = needs_of('16 connect(3<UNIX-STREAM:[9]>, {sa_family=AF_UNIX, sun_path="/run/dbus/system_bus_socket"}, 110) = 0', snapshot)
    assert result.needs == []
    assert any("UNIX" in line for line in result.fixed)


def test_a_terminal_ioctl_on_an_inherited_descriptor_is_not_a_refusal(snapshot):
    result = needs_of('16 ioctl(0</dev/pts/0<char 136:0>>, TCGETS, {c_iflag=ICRNL}) = 0', snapshot)
    assert result.fixed == []


def test_a_terminal_ioctl_on_a_device_the_session_opened_is_a_fixed_refusal(snapshot):
    result = needs_of('16 openat(AT_FDCWD</w>, "/dev/tty", O_RDWR) = 3</dev/tty<char 5:0>>',
                      '16 ioctl(3</dev/tty<char 5:0>>, TCGETS, {c_iflag=ICRNL}) = 0', snapshot)
    assert any("IOCTL_DEV" in line for line in result.fixed)


def test_setsid_is_a_fixed_refusal(snapshot):
    assert any("setsid" in line for line in needs_of("16 setsid() = 16", snapshot).fixed)


def test_openat2_with_resolve_flags_is_judged_by_the_object_it_reached(snapshot):
    line = ('16 openat2(AT_FDCWD</w>, "/etc/hostname", {flags=O_RDONLY|O_CLOEXEC, resolve=RESOLVE_NO_SYMLINKS}, 24)'
            ' = 3</etc/hostname>')
    assert sections_on(needs_of(line, snapshot), "/etc/hostname") == {"read"}


def test_an_o_tmpfile_open_is_unsupported_and_never_silently_dropped(snapshot):
    result = needs_of('16 openat(AT_FDCWD</w>, "/w", O_RDWR|O_TMPFILE, 0600) = 3</w/#1234 (deleted)>', snapshot)
    assert result.needs == []
    assert len(result.unsupported) == 1


def test_fexecve_is_judged_by_the_descriptors_path(tmp_path):
    binary = elf_with_interpreter(tmp_path / "tool", interpreter=str(tmp_path / "ld.so"))
    (tmp_path / "ld.so").write_bytes(b"\x7fELF")
    line = f'16 execveat(3<{binary}>, "", ["tool"], 0x0 /* 1 var */, AT_EMPTY_PATH) = 0'
    result = needs_of(line, snapshot_with(str(tmp_path), str(binary), str(tmp_path / "ld.so")))
    assert sections_on(result, str(binary)) == {"execute", "read"}


def test_an_exchange_needs_both_directions(snapshot):
    result = needs_of('16 renameat2(AT_FDCWD</w>, "/a/x", AT_FDCWD</w>, "/b/y", RENAME_EXCHANGE) = 0',
                      snapshot_with("/a", "/b", "/a/x", "/b/y"))
    assert {"create", "delete", "restructure"} <= sections_on(result, "/a")
    assert {"create", "delete", "restructure"} <= sections_on(result, "/b")
    assert result.moves == {("/a", "/b"), ("/b", "/a")}


def test_an_unmapped_file_call_that_succeeded_is_unsupported(snapshot):
    result = needs_of('16 open_by_handle_at(3</w>, {handle_bytes=8, handle_type=1}, O_RDONLY) = 4</w/f>', snapshot)
    assert len(result.unsupported) == 1
```

`needs_of` builds the calls with `strace_parse.iter_calls` and calls `needs.read_session`; `elf_with_interpreter` writes a minimal 64-bit little-endian ELF header with one `PT_INTERP` program header, so the test needs no compiler.

- [ ] **Step 2: Fail. Step 3: Implement** as A.6; the device test rests on the paths the session opened with a `<char ` or `<block ` decoration. **Step 4: Pass, lint, commit** both paths: `Map every successful call of a recorded session to the section Landlock checks for it`.

### Task R4.2: `generate`

**Files:**
- Create: `var/tmp/helpers/layer_record/generate.py`
- Create: `tests/python/test_layer_record_generate.py`
- Modify: `var/tmp/helpers/layer_record/main.py` (the `generate` subcommand)

**Interfaces:**
- Consumes: `needs.read_session`, `generalise.per_run_grants`, `generalise.grants_for`, `generalise.compact`, `generalise.normalise_hierarchy`, `cfgfile.Policy`, `cfgfile.render`.
- Produces:
  - `generate.Recording(sessions: list[SessionNeeds], snapshots: dict[int, Snapshot], meta: list[dict])` read by `generate.load(recording: pathlib.Path) -> Recording`.
  - `generate.filesystem_grants(recording: Recording) -> tuple[dict[str, frozenset[str]], dict[str, str], list[dict]]`: grants, comments (path to the comment written above it), widenings (each `{"path": str, "reason": str, "observed": list[str], "files_beneath": int}`).
  - `generate.source_covers_destination(grants: dict[str, frozenset[str]], moves: set[tuple[str, str]]) -> dict[str, frozenset[str]]` (A.6.2).
  - `generate.missing_read_or_execute(grants: dict[str, frozenset[str]], snapshots: dict[int, Snapshot]) -> list[str]`, empty when A.7's invariant holds.
  - `generate.write(recording: pathlib.Path, limits: bool, memory_pinned: bool, gate: Callable[[pathlib.Path], tuple[int, str]] = generate.policysystem_gate) -> int`, writing `policy.cfg` and `record.json` and running the acceptance gate; 0, `generate.EXIT_GATE = 5` with the gate's message, or `generate.EXIT_INCOMPLETE = 6` after writing both files when any session has an unsupported call (A.6.4).

- [ ] **Step 1: Failing tests.**

```python
def test_a_move_gives_the_source_every_section_of_the_destination():
    grants = {"/tmp": frozenset({"create", "delete", "restructure"}), "/w": frozenset({"read", "execute", "create", "restructure"})}
    widened = generate.source_covers_destination(grants, {("/tmp", "/w")})
    assert widened["/tmp"] >= widened["/w"]


def test_a_chain_of_moves_settles():
    grants = {"/a": frozenset({"restructure"}), "/b": frozenset({"restructure", "write"}), "/c": frozenset({"restructure", "read"})}
    widened = generate.source_covers_destination(grants, {("/a", "/b"), ("/b", "/c")})
    assert widened["/a"] >= widened["/c"]


def test_no_read_or_execute_row_names_a_path_absent_before_the_sessions():
    grants = {"/w/new-file": frozenset({"read"})}
    assert generate.missing_read_or_execute(grants, {1: snapshot_with("/w")}) == ["/w/new-file"]


def test_a_file_created_and_read_back_is_granted_on_its_pre_existing_parent():
    recording = recording_from_lines([
        '16 openat(AT_FDCWD</w>, "/w/x", O_WRONLY|O_CREAT, 0666) = 3</w/x>',
        '16 openat(AT_FDCWD</w>, "/w/x", O_RDONLY) = 3</w/x>'], snapshot=("/w",))
    grants, _, _ = generate.filesystem_grants(recording)
    assert grants == {"/w": frozenset({"create", "write", "read"})}


def test_a_fine_grained_file_stays_a_file():
    recording = recording_from_lines(['16 openat(AT_FDCWD</w>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>'], snapshot=("/etc", "/etc/hostname"))
    grants, _, _ = generate.filesystem_grants(recording)
    assert grants == {"/etc/hostname": frozenset({"read"})}


def test_a_listed_directory_in_a_fine_grained_root_gets_read_and_a_comment_that_says_what_that_opens():
    recording = recording_from_lines([
        '16 openat(AT_FDCWD</w>, "/etc/ssl/certs", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3</etc/ssl/certs>',
        '16 getdents64(3</etc/ssl/certs>, 0x0 /* 3 entries */, 32768) = 80'], snapshot=("/etc", "/etc/ssl", "/etc/ssl/certs", "/etc/ssl/certs/a.pem"))
    grants, comments, widenings = generate.filesystem_grants(recording)
    assert grants == {"/etc/ssl/certs": frozenset({"read"})}
    assert "makes every file beneath /etc/ssl/certs readable" in comments["/etc/ssl/certs"]
    assert any(widening["path"] == "/etc/ssl/certs" and widening["files_beneath"] == 1 for widening in widenings)


def test_a_file_read_in_a_fine_grained_root_gets_no_listing_comment():
    recording = recording_from_lines(['16 openat(AT_FDCWD</w>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>'], snapshot=("/etc", "/etc/hostname"))
    _, comments, _ = generate.filesystem_grants(recording)
    assert "/etc/hostname" not in comments


def test_a_file_name_with_a_carriage_return_is_granted_on_its_parent_and_listed():
    recording = recording_from_lines(['16 openat(AT_FDCWD</w>, "/srv/data/a\\rb", O_RDONLY) = 3</srv/data/a\\rb>'],
                                     snapshot=("/srv", "/srv/data", "/srv/data/a\rb"))
    grants, _, widenings = generate.filesystem_grants(recording)
    assert grants == {"/srv/data": frozenset({"read"})}
    assert any("a\\x0db" in widening["reason"] for widening in widenings)


def test_an_unsupported_call_makes_generate_say_incomplete(tmp_path):
    recording_dir = recording_directory(tmp_path, lines=['16 openat(AT_FDCWD</w>, "/w", O_RDWR|O_TMPFILE, 0600) = 3</w/#1 (deleted)>'],
                                        snapshot=("/w",))
    assert generate.write(recording_dir, limits=False, memory_pinned=False, gate=lambda path: (0, "")) == generate.EXIT_INCOMPLETE
    assert "INCOMPLETE: 1 recorded calls are not mapped" in (recording_dir / "policy.cfg").read_text()
```

`recording_directory` writes a recording directory with one session and a snapshot under `tmp_path`; `generate.write` takes the acceptance gate as an injectable `gate: Callable[[pathlib.Path], tuple[int, str]]` (default: run `phobos-policysystem.sh`), so the unit test needs no image. That parameter is part of the interface above.

- [ ] **Step 2: Fail. Step 3: Implement**: `per_run_grants` with `own_ids` the union of every session's `process_ids`, then `grants_for`, `compact`, `normalise_hierarchy`, `source_covers_destination`, `normalise_hierarchy` again; `missing_read_or_execute` must be empty or `write` stops before rendering. The header is A.10's, the notes are the fixed refusals; a listed directory inside a fine-grained root gets the comment of A.7. The gate builds its specification in `tempfile.mkdtemp(dir="/var/tmp")` (A.4, defect 4). **Step 4: Pass, lint, commit** the three paths: `Generate a policy from recorded sessions with the layer pruner's own rules`.

### Task R4.3: `check`, and the offline and interactive suites

**Files:**
- Create: `var/tmp/helpers/layer_record/check.py`
- Create: `tests/python/test_layer_record_check.py`
- Modify: `var/tmp/helpers/layer_record/main.py` (the `check` subcommand)
- Create: `tests/integration/record-fixture/session.script`
- Create: `tests/integration/record-fixture/exercise/tool.sh`
- Create: `tests/integration/record-fixture/exercise/old.txt`
- Create: `tests/integration/record_offline.sh` (the checks inside one container)
- Create: `tests/integration/record_offline_host.sh` (starts the recording container and the replay container in turn, since one container cannot start another)
- Create: `tests/integration/record_interactive.sh`
- Modify: `.github/workflows/build.yml`

**Interfaces:**
- Consumes: `strace_parse.iter_calls`, `strace_parse.parse_trace`, `attribute.denials` (PR 162, Task 3.3), `needs.read_session`, `needs.access_pairs`, `pty_script.run`, `observe.tail_chdir`.
- Produces:
  - `check.Refusal(call: Syscall, denial: Denial, pairs: frozenset[tuple[str, str]])`, a replay refusal found by `attribute.denials`, its pairs from `needs.pairs_of_call` on the refused call (never derived from the denial's object and section sets, whose product would invent pairs).
  - `check.compare(recorded: set[tuple[str, str]], replay: list[Refusal]) -> check.Comparison(regressions: list[Refusal], harmless_fixed: list[Refusal], new_behaviour: list[Refusal])`: a regression when any of its pairs was recorded, whatever its layer; `harmless_fixed` for PR 162's `layer == "fixed"` with no recorded pair; `new_behaviour` otherwise.
  - `check.completed(trace: Trace, command: list[str], status: int, stderr_head: str, recorded_statuses: set[int], script_status: int | None) -> list[str]`, the reasons the replay did not run the session, empty when it did: Phobos's own stop (PR 162's status-and-marker rule of its A.6.4), no in-domain `execve` of the command, `pty_script.EXPECT_FAILED`, a status no recorded session ended with.
  - `check.mode(recording: pathlib.Path, container_id: str, fingerprint: dict[str, str], same_container: bool) -> str`, `fingerprint` being the current container's starting state from `snapshot.fingerprint` (A.14): `"fresh-container"` when no session of the recording ran in `container_id` and `fingerprint` equals the recording's first one; otherwise `"same-container"` (the recording's own container) or `"changed-container"` (another container whose fingerprint differs) when `same_container` is set, and `guard.Refused(guard.EXIT_ENVIRONMENT, ...)` naming the container or up to 20 differing paths with what differs when it is not (decision 12).
  - `check.NOT_FRESH_WARNING`, the warning text of A.14, named once.
  - `check.run(recording: pathlib.Path, command: list[str], script: pathlib.Path | None, same_container: bool, resolver: str | None) -> int`: 0 only with no regression and an empty `completed` list, `check.EXIT_REGRESSION = 1` otherwise, `guard.EXIT_ENVIRONMENT` in the recording's own container without `same_container`. It writes `check-<n>/check.json` with `mode`, the three lists of `Comparison`, the `completed` reasons and the statuses, prints the mode in its summary line, and prints `NOT_FRESH_WARNING` before and after the replay in `same-container` and `changed-container` mode.

- [ ] **Step 1: Failing unit tests.**

```python
def test_a_refusal_of_an_access_the_recording_needed_is_a_regression():
    recorded = {("/usr/bin/python3", "execute"), ("/usr/bin/python3", "read")}
    replay = denials_of('20 landlock_restrict_self(3, 0) = 0',
                        '20 execve("/usr/bin/python3", ["python3"], 0x0 /* 1 var */) = -1 EACCES (Permission denied)')
    assert len(check.compare(recorded, replay).regressions) == 1


def test_a_write_refused_where_the_recording_only_read_is_new_behaviour_not_harmless():
    recorded = {("/w/data.txt", "read")}
    replay = denials_of('20 landlock_restrict_self(3, 0) = 0',
                        '20 openat(AT_FDCWD</w>, "/w/data.txt", O_WRONLY) = -1 EACCES (Permission denied)')
    comparison = check.compare(recorded, replay)
    assert comparison.regressions == []
    assert len(comparison.new_behaviour) == 1


def test_a_refused_unix_connect_that_failed_while_recording_too_is_harmless():
    replay = denials_of('20 landlock_restrict_self(3, 0) = 0',
                        '20 connect(3<UNIX-STREAM:[2]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 EACCES (Permission denied)')
    comparison = check.compare(set(), replay)
    assert len(comparison.harmless_fixed) == 1
    assert comparison.regressions == []


def test_a_fixed_refusal_of_an_operation_that_worked_while_recording_is_a_regression():
    recorded = {("unix:/run/dbus/system_bus_socket", "connect")}
    replay = denials_of('20 landlock_restrict_self(3, 0) = 0',
                        '20 connect(3<UNIX-STREAM:[2]>, {sa_family=AF_UNIX, sun_path="/run/dbus/system_bus_socket"}, 110) = -1 EACCES (Permission denied)')
    assert len(check.compare(recorded, replay).regressions) == 1


def test_a_grant_on_one_side_of_a_move_does_not_excuse_the_other():
    recorded = {("/a", "delete"), ("/a", "restructure")}
    replay = denials_of('20 landlock_restrict_self(3, 0) = 0',
                        '20 renameat2(AT_FDCWD</w>, "/a/x", AT_FDCWD</w>, "/b/x", 0) = -1 EXDEV (Invalid cross-device link)')
    [refusal] = replay
    assert ("/b", "create") in refusal.pairs
    assert ("/a", "create") not in refusal.pairs
    assert ("/b", "delete") not in refusal.pairs


def test_a_refusal_before_any_restriction_is_not_counted():
    assert denials_of('20 openat(AT_FDCWD</w>, "/x", O_RDONLY) = -1 EACCES (Permission denied)') == []


def test_a_replay_phobos_stopped_before_the_command_did_not_run_the_session():
    trace = trace_of('20 execve("/var/tmp/opt/core/phobos.sh", ["phobos.sh"], 0x0 /* 1 var */) = 0')
    reasons = check.completed(trace, ["python3"], 11, "Policy invalid: x. (PHB-EPOLICY)", {0}, None)
    assert reasons


def test_a_replay_whose_script_expectation_failed_did_not_run_the_session():
    trace = trace_of('20 landlock_restrict_self(3, 0) = 0', '20 execve("/usr/bin/python3", ["python3"], 0x0 /* 1 var */) = 0')
    assert check.completed(trace, ["python3"], 0, "", {0}, pty_script.EXPECT_FAILED)


def test_a_replay_with_another_status_than_every_recording_did_not_run_the_session():
    trace = trace_of('20 landlock_restrict_self(3, 0) = 0', '20 execve("/usr/bin/python3", ["python3"], 0x0 /* 1 var */) = 0')
    assert check.completed(trace, ["python3"], 1, "", {0}, 0)


def test_a_complete_replay_has_no_reason():
    trace = trace_of('20 landlock_restrict_self(3, 0) = 0', '20 execve("/usr/bin/python3", ["python3"], 0x0 /* 1 var */) = 0')
    assert check.completed(trace, ["python3"], 0, "", {0}, 0) == []


START = {"/": "d 0755", "/etc": "d 0755", "/etc/os-release": "f 0644 386 1700000000000000000",
         "/var/tmp/testing-dir": "d 0755", "/var/tmp/testing-dir/old.txt": "f 0644 4 1700000000000000000"}


def test_another_container_with_the_recordings_starting_state_is_fresh(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    assert check.mode(recording, "bbb", START, same_container=False) == "fresh-container"


def test_an_added_path_is_not_called_fresh(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    changed = START | {"/var/tmp/testing-dir/out.txt": "f 0644 1 1700000000000000001"}
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "bbb", changed, same_container=False)
    assert refused.value.status == guard.EXIT_ENVIRONMENT
    assert "/var/tmp/testing-dir/out.txt" in refused.value.message
    assert check.mode(recording, "bbb", changed, same_container=True) == "changed-container"


def test_a_modified_file_at_an_existing_path_is_not_called_fresh(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    changed = START | {"/etc/os-release": "f 0644 391 1700000000500000000"}
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "bbb", changed, same_container=False)
    assert "/etc/os-release" in refused.value.message


def test_the_fingerprint_sees_contents_change_through_size_and_time_and_skips_docker_files(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "os-release").write_text("A\n")
    (root / "etc" / "hostname").write_text("one\n")
    before = snapshot.fingerprint(root=root)
    (root / "etc" / "os-release").write_text("AB\n")
    (root / "etc" / "hostname").write_text("another\n")
    after = snapshot.fingerprint(root=root)
    assert before["/etc/os-release"] != after["/etc/os-release"]
    assert "/etc/hostname" not in before


def test_the_recordings_own_container_is_refused_without_the_opt_in(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "aaa", START, same_container=False)
    assert refused.value.status == guard.EXIT_ENVIRONMENT


def test_the_opt_in_runs_in_the_same_container_and_says_so(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    assert check.mode(recording, "aaa", START, same_container=True) == "same-container"
    assert "can make it pass where a fresh container would fail" in check.NOT_FRESH_WARNING
```

`recording_with_session` writes a recording directory with one `session.json` naming the given container id and a first snapshot whose fingerprint is the given one.

`denials_of` builds `check.Refusal` objects: `attribute.denials(strace_parse.parse_trace(lines), "/w")` for the refusals, each paired with its refused call and `needs.pairs_of_call` of it against a snapshot holding `/a`, `/b`, `/a/x` and `/w`; `trace_of` runs `strace_parse.parse_trace`.

- [ ] **Step 2: Fail. Step 3: Implement**; `run` writes the `timeout=0` overlay to `/var/tmp/phobos-record-overlay.cfg` (outside every write path), runs `strace -DDD -f -qq -yy -o <recording>/check-<n>/trace phobos.sh [--resolver r] --config policy.cfg --config <overlay> -- <command>` in the tail's `--chdir` after copying the exercise afresh, typed by `pty_script.run` when a script is given, then checks `completed` and `compare` and writes `check.json`. **Step 4: Pass.**
- [ ] **Step 5: Write the fixture and the offline suite.** `session.script` drives `python3 -q -i` through the spike's steps (A.4) except the network ones, each step printing an `OK-<n>` marker; `record_offline.sh`, in the prune image with `--network none`:
  1. container A: `phobos-record record --name s --script session.script -- python3 -q -i`, then `phobos-record generate --name s`; both status 0;
  2. container A, still, both directions of decision 12: `phobos-record check --name s --script session.script -- python3 -q -i` without the opt-in ends with status 3 and runs nothing; with `--same-container` it runs, prints the warning of A.14 before and after the replay, and `check.json` records `"mode": "same-container"`;
  3. container B, new from the image: `phobos-record check --name s --script session.script -- python3 -q -i`, status 0, the report names 0 regressions, prints no warning, and `check.json` records `"mode": "fresh-container"`; then, in a container C that first runs `touch /var/tmp/leftover`, and in a container D that first appends one line to `/etc/os-release` (an existing path), the same command ends with status 3 naming that path, which shows that neither an added nor a modified file lets a changed container be called fresh;
  4. container B, forbidden direction: PR 162's containment checks under `policy.cfg` (a canary at `/root/phobos-record-canary` and at `/srv/phobos-record-canary/secret` refused for read; a write into `/usr/share/doc` refused; `connect 10.0.0.1:80` and `bind 8080` refused), and `/opt/java/openjdk/release`, read by the session, readable;
  5. container B, the gate in the other direction: `policy.cfg` with `/var/tmp/testing-dir/never-existed` appended to `[read]` is refused by `phobos-policysystem.sh` with status 11, which shows the gate would have caught a missing path.
- [ ] **Step 6: Write `record_interactive.sh`**: `bash -i` in a pseudo-terminal (Python's `pty`, as the spike's `drive_session.py`), `phobos-record record --name i -- python3 -q`, then Ctrl+C during `time.sleep(60)` (expect `KeyboardInterrupt` and a working prompt), Ctrl+Z (expect `Stopped`), `fg` (expect the same Python to answer), `exit()`, the recorder's status equal to Python's, and the traceback and a later write to standard error visible in the recording's terminal; a session `sh -c 'sleep 2 & exit 0'` whose trace still holds the `sleep`'s `exit_group`, showing the recorder waited for the tracer. The same keystrokes are then replayed with `check` in a second container: the suite requires 0 regressions and an empty `completed` list.
- [ ] **Step 7: Run both against the prune image**: `bash tests/integration/record_offline_host.sh phobos-prune-layers:local`, which runs `docker run --rm --network none -v "$PWD:/repo:ro" -v "$PWD/var/tmp/helpers:/var/tmp/helpers:ro" -v "<scratch>:/var/tmp/recordings" --entrypoint bash phobos-prune-layers:local /repo/tests/integration/record_offline.sh <phase>` once with the phase `record` (container A) and once with `replay` (container B), and `bash tests/integration/record_interactive.sh` inside the same image the same way. Expected: every check passed, 0 regressions.
- [ ] **Step 8: Wire into `build.yml`, lint, commit** the ten paths by name: `Replay a recorded session under the real layers and fail on every refusal of what succeeded`.

## PR R5: Network endpoints and names

### Task R5.1: Names from TLS, DNS and the hosts file

**Files:**
- Create: `var/tmp/helpers/layer_record/names.py`
- Create: `tests/python/test_layer_record_names.py`
- Create: `tests/python/fixtures/record/` (a captured DNS response for `example.org` with `A` and `AAAA`, one with a `CNAME`, a TLS 1.3 ClientHello from Python's `ssl` with SNI, one from `openssl s_client -noservername` without)

**Interfaces:**
- Produces: `names.dns_answers(message: bytes) -> list[tuple[str, str]]` (address, asked name), `names.client_hello_server_name(record: bytes) -> str | None`, `names.hosts_file(text: str) -> dict[str, str]` (address to first name), each never raising on malformed input and returning raw names; `names.valid_hostname(name: str) -> str | None`, the lower-cased name when it matches A.7's DNS grammar and is not an address, `None` otherwise, which every caller applies before a name may become a rule.

- [ ] **Step 1: Failing tests.**

```python
def test_a_and_aaaa_answers_map_to_the_name_asked():
    answers = names.dns_answers((FIXTURES / "example-org.dns").read_bytes())
    assert ("172.66.157.237", "example.org") in answers
    assert all(name == "example.org" for _, name in answers)


def test_a_cname_chain_maps_to_the_name_asked_not_the_alias():
    answers = names.dns_answers((FIXTURES / "cname.dns").read_bytes())
    assert {name for _, name in answers} == {"www.example.org"}


def test_a_query_is_not_an_answer():
    assert names.dns_answers(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00") == []


def test_a_truncated_message_gives_no_answer_and_no_exception():
    assert names.dns_answers((FIXTURES / "example-org.dns").read_bytes()[:20]) == []


def test_the_server_name_of_a_client_hello():
    assert names.client_hello_server_name((FIXTURES / "hello-sni.bin").read_bytes()) == "example.org"


def test_a_client_hello_without_a_server_name():
    assert names.client_hello_server_name((FIXTURES / "hello-no-sni.bin").read_bytes()) is None


def test_application_data_is_not_a_client_hello():
    assert names.client_hello_server_name(b"\x17\x03\x03\x00\x05hello") is None


@pytest.mark.parametrize("name", ["api.phobos.test", "API.Phobos.Test", "a-b.example.org"])
def test_a_dns_name_is_a_valid_host_name(name):
    assert names.valid_hostname(name) == name.lower()


@pytest.mark.parametrize("name", ["evil\n[write]\n/", "a..b", "-a.example.org", "a" * 64 + ".org",
                                  "192.0.2.7", "::1", "a b.org", "", "*.example.org", "example.org."])
def test_anything_else_is_not(name):
    assert names.valid_hostname(name) is None


def test_a_dns_answer_for_an_injected_name_yields_a_name_that_is_never_valid():
    answers = names.dns_answers(dns_response(question=b"x\n[write]\n/", address="192.0.2.7"))
    assert answers == [("192.0.2.7", "x\n[write]\n/")]
    assert names.valid_hostname(answers[0][1]) is None


def test_a_client_hello_naming_an_injection_yields_a_name_that_is_never_valid():
    name = names.client_hello_server_name(client_hello_with_server_name(b"x\n[write]\n/"))
    assert name is not None
    assert names.valid_hostname(name) is None
```

`client_hello_with_server_name` builds a minimal TLS 1.2 ClientHello around the given bytes, and `dns_response` a response with one question label holding the given bytes and one `A` answer, both in the test module. Task R5.2 adds the end-to-end case: a session whose DNS answer names `x\n[write]\n/` and which then connects to that address without TLS gives `allow 192.0.2.7:80` with the name escaped in its comment, and `cfgfile.read_policy` of the result has no `[write]` section.

- [ ] **Step 2: Fail. Step 3: Implement** from the spike's `dns_answers`, `dns_name_at` and `client_hello_server_name`, with a jump limit on compression pointers and bounds checks on every read. **Step 4: Pass, lint, commit** the three paths: `Recover host names from TLS client hellos, DNS answers and the hosts file`.

### Task R5.2: Endpoints to rules

**Files:**
- Create: `var/tmp/helpers/layer_record/endpoints.py`
- Create: `tests/python/test_layer_record_endpoints.py`
- Modify: `var/tmp/helpers/layer_record/needs.py` (endpoints, ports held, names seen)
- Modify: `var/tmp/helpers/layer_record/generate.py` (the network sections)

**Interfaces:**
- Consumes: `names.*`, `network.loopback_wildcard`, `cfgfile.Rule`.
- Produces:
  - `needs.SessionNeeds` gains `endpoints: list[endpoints.Endpoint]`, `held: set[tuple[str, str, int]]` (family, transport, port, from `bind` and `listen` only, A.8.1), `sent: set[tuple[str, int]]`, `pending: set[tuple[str, int]]` (remote ends of `EINPROGRESS` connects), `connected: set[tuple[str, int]]` (remote ends of every connected stream socket a decoration showed, from any process), `incomplete: list[endpoints.Endpoint]` (pending and never connected), `server_names: dict[tuple[str, int], str]`, `dns_names: dict[str, str]`, `accepted: set[tuple[str, int]]`.
  - `endpoints.Endpoint(address: str, port: int, transport: str, call: str)`.
  - `endpoints.rules(sessions: list[SessionNeeds], hosts: dict[str, str]) -> endpoints.NetworkRules(connect: tuple[cfgfile.Rule, ...], bind: tuple[cfgfile.Rule, ...], notes: tuple[str, ...], needs_resolver: bool)`.

- [ ] **Step 1: Failing tests**, each from strace lines through `needs.read_session` and `endpoints.rules`:

```python
def test_a_loopback_port_the_session_bound_becomes_the_loopback_wildcard():
    rules = rules_of('16 bind(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
                     '16 listen(3<TCP:[127.0.0.1:40623]>, 128) = 0',
                     '17 connect(4<TCP:[2]>, {sa_family=AF_INET, sin_port=htons(40623), sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
    assert texts(rules.connect) == ("allow 127.0.0.1:*",)
    assert texts(rules.bind) == ("allow 0",)


def test_a_loopback_port_nobody_in_the_session_bound_is_exact_and_explained():
    rules = rules_of('17 connect(4<TCP:[2]>, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
    assert texts(rules.connect) == ("allow 127.0.0.1:5432",)
    assert "must exist at grading time" in rules.connect[0].comment


def test_a_datagram_connect_that_sent_nothing_is_not_granted():
    rules = rules_of('16 connect(5<UDP:[3]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("104.20.26.136")}, 16) = 0')
    assert rules.connect == ()
    assert any("104.20.26.136:443" in note for note in rules.notes)


def test_a_tls_server_name_becomes_a_name_rule_and_asks_for_a_resolver():
    rules = rules_of('16 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("172.66.157.237")}, 16) = -1 EINPROGRESS (Operation now in progress)',
                     '16 write(3<TCP:[172.17.0.2:32972->172.66.157.237:443]>, ' + hello_sni_argument("example.org") + ', 517) = 517')
    assert texts(rules.connect) == ("allow example.org:443",)
    assert rules.needs_resolver


def test_without_tls_the_address_is_granted_and_the_name_is_a_comment():
    rules = rules_of(dns_answer_line("plain.example.org", "192.0.2.7"),
                     '16 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.7")}, 16) = 0')
    assert "allow 192.0.2.7:80" in texts(rules.connect)
    assert "plain.example.org" in next(rule.comment for rule in rules.connect if rule.text == "allow 192.0.2.7:80")


def test_an_ipv4_mapped_destination_is_written_as_ipv4():
    rules = rules_of('16 connect(3<TCPv6:[1]>, {sa_family=AF_INET6, sin6_port=htons(80), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::ffff:192.0.2.7", &sin6_addr), sin6_scope_id=0}, 28) = 0')
    assert texts(rules.connect) == ("allow 192.0.2.7:80",)


def test_a_udp_bind_does_not_make_a_tcp_connection_to_the_same_port_look_owned():
    rules = rules_of('16 bind(3<UDP:[1]>, {sa_family=AF_INET, sin_port=htons(40000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
                     '17 connect(4<TCP:[2]>, {sa_family=AF_INET, sin_port=htons(40000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
    assert texts(rules.connect) == ("allow 127.0.0.1:40000",)


def test_a_client_sockets_own_port_is_not_held():
    rules = rules_of('17 connect(4<TCP:[2]>, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
                     '17 getsockname(4<TCP:[127.0.0.1:41000->127.0.0.1:5432]>, {sa_family=AF_INET, sin_port=htons(41000), sin_addr=inet_addr("127.0.0.1")}, [128 => 16]) = 0',
                     '18 connect(5<TCP:[3]>, {sa_family=AF_INET, sin_port=htons(41000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0')
    assert "allow 127.0.0.1:*" not in texts(rules.connect)


def test_a_non_blocking_connect_never_seen_to_complete_is_not_granted():
    rules = rules_of('16 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.7")}, 16) = -1 EINPROGRESS (Operation now in progress)',
                     '16 getsockopt(3<TCP:[1]>, SOL_SOCKET, SO_ERROR, [ECONNREFUSED], [4]) = 0')
    assert rules.connect == ()
    assert any("never completed" in note for note in rules.notes)


def test_a_non_blocking_connect_that_completed_is_granted():
    rules = rules_of('16 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.7")}, 16) = -1 EINPROGRESS (Operation now in progress)',
                     '16 getsockopt(3<TCP:[172.17.0.2:50000->192.0.2.7:80]>, SOL_SOCKET, SO_ERROR, [0], [4]) = 0')
    assert texts(rules.connect) == ("allow 192.0.2.7:80",)


def test_completion_seen_in_a_child_after_fork_counts():
    rules = rules_of('16 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.7")}, 16) = -1 EINPROGRESS (Operation now in progress)',
                     '16 clone(child_stack=NULL, flags=SIGCHLD) = 17',
                     '17 write(3<TCP:[172.17.0.2:50000->192.0.2.7:80]>, "GET / HTTP/1.0\\r\\n\\r\\n", 18) = 18')
    assert texts(rules.connect) == ("allow 192.0.2.7:80",)


def test_a_reused_descriptor_number_does_not_complete_another_connect():
    rules = rules_of('16 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.7")}, 16) = -1 EINPROGRESS (Operation now in progress)',
                     '16 close(3<TCP:[1]>) = 0',
                     '16 connect(3<TCP:[2]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.0.2.8")}, 16) = 0',
                     '16 getsockopt(3<TCP:[172.17.0.2:50001->192.0.2.8:443]>, SOL_SOCKET, SO_ERROR, [0], [4]) = 0')
    assert "allow 192.0.2.7:80" not in texts(rules.connect)
    assert "allow 192.0.2.8:443" in texts(rules.connect)


def test_an_invalid_server_name_falls_back_to_the_address():
    rules = rules_of('16 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.0.2.7")}, 16) = 0',
                     '16 write(3<TCP:[172.17.0.2:32972->192.0.2.7:443]>, ' + hello_sni_argument("x\n[write]\n/") + ', 517) = 517')
    assert texts(rules.connect) == ("allow 192.0.2.7:443",)
    assert not rules.needs_resolver


def test_an_outside_peer_becomes_an_accept_note_and_no_rule():
    rules = rules_of('16 accept4(3<TCP:[0.0.0.0:8080]>, {sa_family=AF_INET, sin_port=htons(51000), sin_addr=inet_addr("203.0.113.9")}, [16], SOCK_CLOEXEC) = 4')
    assert any(note.startswith("[accept] not generated") for note in rules.notes)
```

- [ ] **Step 2: Fail. Step 3: Implement** A.8. **Step 4: Pass, lint, commit** the four paths: `Turn the endpoints a session reached into connect and bind rules`.

### Task R5.3: The networked suite

**Files:**
- Create: `tests/integration/record-network-server/Dockerfile` (`FROM` the prune image; `python3` serves TLS on 443 with a certificate for `api.phobos.test` generated at start, and answers DNS for that name on 53/udp; standard library only)
- Create: `tests/integration/record-network-server/serve.py`
- Create: `tests/integration/record_networked.sh`
- Modify: `.github/workflows/build.yml`

- [ ] **Step 1: Write the suite.** From the job: `docker network create --internal phobos-record-test` (no route out); start the server container on it, read its address; recording container on the same network with `--dns <server>`: a script that opens `https://api.phobos.test/` with `ssl` verification off and prints `OK-E1`, then `generate`. Assert in `policy.cfg`: `allow api.phobos.test:443`, the header line about `--resolver`, no rule naming port 53 uncommented. Replay container on the same network: `check --resolver <server>` with 0 regressions. Forbidden direction in the replay container: a connection to `<server>:8443` and to `api.phobos.test:8443` refused with `EACCES`. Remove the network and the server at the end, by the names this suite gave them only.
- [ ] **Step 2: Run it locally** (every container ordinary, no capability). Expected: all passed. **Step 3: Wire into `build.yml`, lint (`hadolint`, `shellcheck`, `ruff`, `actionlint`), commit** the four paths: `Prove a recorded host name replays through the egress broker on an isolated network`.

## PR R6: Several sessions, and the diff

### Task R6.1: Merging sessions

**Files:**
- Modify: `var/tmp/helpers/layer_record/generate.py`
- Modify: `tests/python/test_layer_record_generate.py`
- Modify: `tests/integration/record_offline.sh`

**Interfaces:**
- Produces: `generate.load` reads every `sessions/<n>/` and its snapshot; `generate.ImageMismatch(images: set[str])` raised when sessions name different image ids.

- [ ] **Step 1: Failing tests**: two sessions, one reading `/etc/hostname`, one `/etc/hosts`, give both rows; a per-run component `/proc/<n>/stat` seen as two different pids in two sessions is granted on `/proc` with the comment naming both; sessions from two image ids raise `ImageMismatch`; a file the first session created in its container is "created" for the second session in the same container (one snapshot per container).
- [ ] **Step 2: Fail. Step 3: Implement. Step 4: Extend the suite**: a second scripted session doing something the first did not (reading a different file in a fine-grained root), recorded in a third container; the merged `policy.cfg` replays both scripts with 0 regressions; the first-session-only policy fails `check` for the second script with exactly the missing row as a regression, which proves the check in the forbidden direction. **Step 5: Pass, lint, commit** the three paths: `Merge several recorded sessions into one policy`.

### Task R6.2: `diff`

**Files:**
- Create: `var/tmp/helpers/layer_record/diff.py`
- Create: `tests/python/test_layer_record_diff.py`
- Modify: `var/tmp/helpers/layer_record/main.py`

**Interfaces:**
- Consumes: `cfgfile.read_policy`, `generate.load`, `needs.SessionNeeds`, `endpoints.rules`.
- Produces: `diff.compare(recording: Recording, policy: Policy) -> diff.Report(missing: list[str], unused: list[str], covered_by_ancestor: list[str])`, `diff.render(report: Report) -> str`; `phobos-record diff --name <n>... --policy <cfg>` prints it and never writes a file.

- [ ] **Step 1: Failing tests.**

```python
def test_a_need_no_rule_covers_is_missing():
    report = diff.compare(recording_needing(("/etc/hostname", "read")), cfgfile.read_policy("[read]\n/usr\n"))
    assert report.missing == ["[read] /etc/hostname"]


def test_an_ancestor_rule_covers_a_need():
    report = diff.compare(recording_needing(("/usr/lib/x.so", "read")), cfgfile.read_policy("[read]\n/usr\n"))
    assert report.missing == []


def test_a_rule_no_session_touched_is_unused():
    report = diff.compare(recording_needing(("/usr/lib/x.so", "read")), cfgfile.read_policy("[read]\n/usr\n/opt\n"))
    assert report.unused == ["[read] /opt"]


def test_a_rule_an_ancestor_covers_is_marked_and_not_called_unused():
    report = diff.compare(recording_needing(("/usr/bin/ls", "read")), cfgfile.read_policy("[read]\n/usr\n/usr/bin\n"))
    assert "[read] /usr/bin" in report.covered_by_ancestor
    assert "[read] /usr/bin" not in report.unused


def test_an_endpoint_no_rule_admits_is_missing():
    report = diff.compare(recording_reaching(("192.0.2.7", 80, "tcp")), cfgfile.read_policy("[connect]\nallow 127.0.0.1:*\n"))
    assert report.missing == ["[connect] 192.0.2.7:80 tcp"]
```

- [ ] **Step 2: Fail. Step 3: Implement**; covered means the union of the rights of every rule at or above the path (both spellings of a symbolic link folded through `os.path.realpath`), with rights as the enforcer's letters. **Step 4: Extend `record_offline.sh`**: `diff` against `${PHOBOS_HOME}`'s copy of `core/config/BaseLanguage-java.cfg` (mounted from the repository) lists `[read] /etc/hostname` as covered (the base grants `/etc`) and names at least `[create-ipc] /root/.gradle` as unused, and leaves the file byte-identical (`cmp`). **Step 5: Pass, lint, commit** the four paths: `List what a policy lacks and what it grants that no session used`.

## PR R7: Optional limits

### Task R7.1: Limits from a recorded session

**Files:**
- Modify: `var/tmp/helpers/layer_record/observe.py` (PR 162's sampler beside the session, the tracer excluded)
- Modify: `var/tmp/helpers/layer_record/generate.py`
- Create: `tests/python/test_layer_record_limits.py`

**Interfaces:**
- Consumes: `sampler.Sampler`, `limits.Measurement`, `limits.Margins`, `limits.margins` (PR 162, Task 7.1).
- Produces: `observe.record_session(..., sample: bool)` writes `sessions/<n>/samples.json`; `generate.derived_limits(meta: list[dict], measurements: list[Measurement], memory_pinned: bool) -> tuple[dict[str, int], list[str]]` (limits, and the header lines saying which were not derived and why).

- [ ] **Step 1: Failing tests.**

```python
def test_an_interactive_session_derives_no_timeout_and_says_so():
    values, header = generate.derived_limits([{"interactive": True}], [measurement(wall=600.0, cpu=12.0)], memory_pinned=False)
    assert "timeout" not in values
    assert any("wall clock" in line for line in header)


def test_only_batch_sessions_derive_a_timeout_with_the_shared_margin():
    values, _ = generate.derived_limits([{"interactive": False}], [measurement(wall=41.0, cpu=12.0)], memory_pinned=False)
    assert values["timeout"] == 210


def test_memory_only_when_the_instructor_says_it_is_pinned():
    values, _ = generate.derived_limits([{"interactive": False}], [measurement(wall=1.0, cpu=1.0, vm=2300.0)], memory_pinned=False)
    assert "mem_mb" not in values
    pinned, _ = generate.derived_limits([{"interactive": False}], [measurement(wall=1.0, cpu=1.0, vm=2300.0)], memory_pinned=True)
    assert pinned["mem_mb"] == 4608
```

(`timeout = max(60, ceil_to(5 x 41, 30)) = 210`; `mem_mb = max(512, ceil_to(2 x 2300, 256)) = 4608`, PR 162's formulas with its decision 3 margins.)

- [ ] **Step 2: Fail. Step 3: Implement**; the sampler skips processes whose `comm` is `strace`. **Step 4: Extend `record_offline.sh`**: `generate --limits` on a batch session of the fixture writes `cpu`, `nproc`, `nofile`, `fsize_mb` and `timeout` and no `mem_mb`; the replay passes under them; a probe exceeding `nofile` prints `errno=EMFILE` under them. **Step 5: Pass, lint, commit** the three paths: `Derive optional limits from a recorded session, never a timeout from an interactive one`.

## PR R8: Documentation

### Task R8.1: README, CLAUDE.md and SECURITY.md

**Files:**
- Modify: `README.md` (a section "Recording a reference program", after the prune section PR 162 rewrites)
- Modify: `CLAUDE.md` (project structure: `var/tmp/helpers/layer_record/`; overview: the recorder as the interactive companion of the layer pruner)
- Modify: `SECURITY.md` (one paragraph: the recorder runs a program unconfined while it records, exists only in the prune image, and must never be pointed at an untrusted submission)

- [ ] **Step 1: Write** the three changes, every command quoted in them taken from the suites of R4 to R6 and run once as written. **Step 2:** `ec --no-color`. **Step 3: Commit** the three paths: `Document the recording pruner and what it must never be used for`. If PR 122 (the Docusaurus site) has merged by then, the README text goes into its contributor pages instead, as PR 162's A.12 also says for its own documentation.

---

# Part C: Review record

An independent reviewer read this plan against the code it cites, the two sibling plans (PR 162 and PR 166) and the spike's outputs. The first draft took three rounds and was approved in the third ("I approve the plan as revised."). Markus's decisions 12 to 14 (A.20) then changed the plan, and that revision was reviewed again in the same session from round 4 on, recorded below; the round 3 approval covers only the earlier revision.

Round 1 did not approve and raised nine points:

| Severity | Point | Resolution |
| --- | --- | --- |
| high | observed host names and paths could inject lines into the policy | A.7, "Observed text is untrusted": control characters refused in paths, a DNS grammar for any name that becomes a rule, every comment escaped; fixtures for an injected server name and a carriage return (R2.3, R4.2, R5.1, R5.2) |
| high | the replay check matched by call name and object, so a recorded read could excuse a refused write | A.14: access signatures (object, section), "new behaviour" kept apart from "harmless" (R4.3) |
| high | no refusal did not prove the replay ran the session | A.14: `check.completed` fails on Phobos's own stop, no in-domain `execve`, an unmet scripted expectation, an unrecorded exit status; a by-hand replay is not called a proof |
| high | held ports lost their transport, and a client socket's port counted as held | A.8.1: held endpoints keyed by family, transport and port, from `bind` and `listen` only (R5.2) |
| high | device ioctl is refused only from Landlock version 5 | partly agreed: every fixed refusal names its layer and version, written against the recorded ABI; pinning a grading ABI stays the operator's tail flag (A.6.3) |
| high | the mapping missed `O_TMPFILE`, `fexecve`, `openat2` resolve flags, and treated `EINPROGRESS` as success | A.6.1 rows, A.6.4 (unsupported calls make the result incomplete, status 6), `EINPROGRESS` only with seen completion (A.8.1); `RENAME_EXCHANGE` was already a row and gained a test |
| high | F1 and F2 unresolved | partly agreed: `core/` is out of scope; Markus later decided each gets its own pull request against `core/` (decision 14), so this plan only refers to them (A.19) |
| medium | the safety checks were overstated | A.10 separates the structural guarantee from safeguards against mistakes; `sh phobos.sh` is caught and tested, a wrapper is said not to be |
| medium | `/etc/hosts` contents were never captured | the snapshot copies it (A.8.3, R3.1) |

Round 2 accepted seven of those and found three gaps: a DNS injection fixture was promised but not listed; pairing every object of a refusal with every section could invent pairs; and a fixed refusal of an operation that had succeeded while recording would have passed the check. All three were fixed: R5.1 gained the DNS fixture and an end-to-end case, refusals are turned into object-specific pairs by the recorder's own mapping (`needs.pairs_of_call`), and fixed operations have pairs of their own, so their refusal is a regression when they worked bare. The reviewer also asked that `EINPROGRESS` completion survive `fork` and descriptor reuse, which A.8.1 now keys by the remote end in the decoration. Round 3 approved.

Round 4 reviewed the revision for decisions 12 to 14. It found the three changes consistent but did not approve: `check` called any container other than the recording's "fresh" without creating or verifying one, so a reused container could be reported as fresh. `check` now verifies freshness itself: before the replay it lists the container's paths with the snapshot's rules and compares them with the recording's first snapshot; only an equal listing in another container is `fresh-container`, and a container whose listing differs is refused, or with the opt-in runs as `changed-container` with the warning (A.14, Task R4.3, and a container C in the offline suite that is refused for one leftover file). The reviewer also asked that this record keep the earlier approval apart from the review of this revision, which the opening paragraph now does.

Round 5 did not approve either: a listing of paths catches an added file but not a modified one. The comparison is now a starting-state fingerprint (type, and for a regular file mode, size and modification time in nanoseconds, a link's target, a directory's mode), with the files Docker writes per container left out; `fresh-container` means exactly that the fingerprint matched, and A.14 states that a change keeping size and modification time is not detected. A unit test and a container D in the offline suite show a modified file at an existing path refused.

Round 6 approved this revision explicitly: "I approve the plan as revised." Its one wording note, that a tool can replace a file and preserve its times so a time reset is not the only cause of an undetected change, is applied in A.14.
