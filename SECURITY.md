# Phobos Security Policy

## Supported Versions

Currently, the only supported version is whatever is on `main`. This is a research artefact
rather than a released product, so there are no release lines and no maintained release
branches.

## Deliberately dangerous code

Phobos is a sandbox, so parts of it exist to do things a normal project would avoid, and the
rest exists to take privileges away. None of the following is a vulnerability.

- `core/` applies the sandbox. `phobos.sh` and the scripts beside it, and the
  `phobos-landlock` program they run, build a Landlock policy from an allow-list and grant
  back only what the allow-list names, then restrict the process so it and everything it
  starts can only lose access. Code that assembles access rules from a configuration file
  looks like path injection, and is the mechanism. It needs no privilege: a task may always
  restrict itself further.
- `ld_preloader/` and the `libnetblocker.so` beside it intercept network calls through
  `LD_PRELOAD`, hooking name resolution, `connect`, `bind`, and `sendto` and `sendmsg` for
  the datagrams a UDP socket names without connecting, refusing outbound hosts an allow-list
  does not name and narrowing a local TCP bind to the addresses a `[bind]` allow-list names.
  Function interposition of libc symbols is what the component is for. It is
  defence in depth rather than a boundary: a process can step around a preload library.
- `core/phobos-connect-guard.c` is the connect guard. When the network layer is on it
  supervises every `connect()` with a seccomp user-notification and makes an allowed
  connection itself from outside the sandboxed process, so for `connect` it is a boundary a
  raw system call cannot step around, enforcing the `[connect]` allow-list by host and port.
  It reads the destination address of the connect, so it holds a rule that names an IP literal
  (and the name `localhost`) to that exact address, and a rule that names a DNS hostname it
  cannot tie to an address there to its port alone, leaving that host to libnetblocker. Since
  seccomp stops the call before the kernel path where Landlock would check the port, the guard
  connects outside Landlock and so is the whole connect boundary where it runs; Landlock's
  `--connect-tcp` ports remain a second, kernel-enforced expression of the same ports. A
  `connect` of a family the guard does not carry (a UNIX-domain socket) is refused rather than
  made outside the Landlock view the command is held to. The boundary for external egress
  beyond the allow-list, and for UDP, is still a container started with `--network none`.
- `docker/prune_phase/` runs the discovery phase, which deliberately breaks a build over and
  over: it hides a directory, runs the tests, and concludes from the failure that the
  directory was needed. Its orchestrator therefore starts processes and interprets their
  failures, and its output becomes the allow-list the sandbox later trusts. The discovery
  phase uses Bubblewrap to hide directories; the sandbox an exercise runs in does not.
- The Dockerfiles under `docker/` extend the Artemis test images and compile the C products.
  The run-phase image needs no user namespaces, no added capabilities and no security
  options: Landlock, the preload library and the timeout are all self-imposed by the
  unprivileged process. The container the grader starts should add `--network none` and
  cgroup limits, which are the outer boundary Phobos cannot set from inside itself.

A committed `libnetblocker.so` is a compiled artefact in version control. It is there so
Phobos can run from a checkout without a compiler. CI rebuilds it from the C source beside it
with a pinned toolchain and fails when the bytes differ, and holds the copy the run-phase image
builds to the same bytes. It is built for x86-64; where the loader cannot use it, the network
layer refuses to start rather than running the command unfiltered.

## Threat model, in one paragraph

Phobos defends the *grading machine* against untrusted student code executed during a test
run. It does not defend the student's own submission from anything, and it is not a general
containment boundary against a determined attacker with local privilege. The allow-list is
derived empirically by the pruning phase, so it is only as tight as the reference exercises
that produced it: a resource no reference exercise touched is hidden, and a resource one of
them touched is permitted for every submission thereafter.

## Scope

A report is in scope when Phobos fails at what it claims to do, or when it causes harm nobody
asked for. Concretely:

- a submission reaching a file, or a TCP port Landlock was given, that the active allow-list
  does not permit
- the sandbox failing open, that is, running the tests unconfined while reporting success
- the pruning phase writing an allow-list that grants more than the runs it observed required
- privilege escalation out of the sandbox onto the host
- any defect in this repository's own scripts that damages the machine running them beyond
  the working tree they were pointed at

Out of scope: the deliberately dangerous code listed above, anything the container's own
settings are responsible for rather than Phobos (external network and UDP, which
`--network none` closes, and the hard resource caps, which cgroups set), JVM-internal
attacks that never touch the operating system, which are Ares's responsibility, and anything
that follows from running the discovery phase against a project you were not willing to have
repeatedly broken.

## Reporting a bug

If the problem relates to a bug that is associated with unexpected behaviour or
inconvenience or something non-critical is broken, simply report it as a bug and use the
[issues](https://github.com/ls1intum/phobos/issues) for that.

## Reporting a Vulnerability

If the problem relates to a vulnerability that could be used maliciously or is in another
way a security issue, please do not make the issue public. Instead, collect the following
information first:
- as with a bug report, describe how the vulnerability can be reproduced
- state the commit, the allow-list in use and the language environment the run used
- state the kernel and whether the run was inside a container, since the enforcement
  mechanism depends on both
- provide any additional information and context, if possible

Then report it through [GitHub's private vulnerability
reporting](https://github.com/ls1intum/phobos/security/advisories/new), which is enabled
on this repository. The report stays private while it is assessed and remediated.
