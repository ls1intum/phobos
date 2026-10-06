# Phobos Security Policy

## Supported Versions

Currently, the only supported version is whatever is on `main`. This is a research artefact
rather than a released product, so there are no release lines and no maintained release
branches.

## Deliberately dangerous code

Phobos is a sandbox, so parts of it exist to do things a normal project would avoid, and the
rest exists to take privileges away. None of the following is a vulnerability.

- `core/` applies the sandbox. `phobos.sh` and the scripts beside it, and the
  `phobos-landlock-filesystem-and-networksystem` program they run, build a Landlock policy from an allow-list and grant
  back only what the allow-list names, then restrict the process so it and everything it
  starts can only lose access. Code that assembles access rules from a configuration file
  looks like path injection, and is the mechanism. It needs no privilege: a task may always
  restrict itself further.
- `core/phobos-seccomp-networksystem/phobos-seccomp-networksystem.c` is the connect guard. When the network layer is on it
  supervises every `connect()` with a seccomp user-notification and makes an allowed
  connection itself from outside the sandboxed process, so for `connect` it is a boundary a
  raw system call cannot step around, enforcing the `[connect]` allow-list by host and port.
  It reads the destination address of the connect, so it holds a rule that names an IP literal
  to that exact address, the name `localhost` to the loopback range (every `127.x.x.x` address and
  `::1`), a rule that names an IP range to that network, and a rule that names a DNS hostname it cannot tie to an address there to its port
  alone. Such a hostname rule's host is enforced by the egress broker, an HAProxy the network
  layer starts automatically for such a rule and that checks the TLS host name the guard cannot
  see; the network layer refuses an exact-name rule when no resolver is given, so an instructor
  who needs a rotating, CDN-backed host either gives a resolver or names its address range rather
  than its name. Since seccomp stops the call before the kernel path where Landlock would check the
  port, the guard connects outside Landlock and so is the whole connect boundary where it runs;
  Landlock's `--connect-tcp` ports remain a second, kernel-enforced expression of the same
  ports. That second expression is absent for a transport whose rules include a loopback rule that
  names no port, which the shipped policies carry: Landlock cannot keep loopback open on every
  port and close the rest, so a rule that names a port beside it is enforced by the guard alone,
  and the network layer logs the ports that applies to. For udp this also means that such a rule does not need Landlock
  version 10. A `connect` of a family the guard does not carry (a UNIX-domain socket) is refused
  rather than made outside the Landlock view the command is held to. A `[connect]`/`[bind]` rule may
  carry a `udp` transport marker: the guard enforces it for the UDP transport apart from TCP, and
  Landlock's `--connect-udp`/`--bind-udp` (the version-10 UDP rights) are its second, kernel-enforced
  expression. UDP needs Landlock version 10, so a udp rule that names a concrete port is refused on
  an older kernel rather than left unenforced, except a `[connect]` rule beside a udp loopback
  wildcard, which Landlock cannot express with any
  version and which leaves such a rule to the guard alone. A udp rule may name an exact host: a datagram carries no TLS host name for the
  egress broker to read, so the network layer resolves the name once, before the command starts,
  through the resolver the operator gave, hands the guard a rule for each address (at most sixteen) and
  shows the command the same addresses in `/etc/hosts`. The rule is held to what the name led to at
  the start of the run, which is a snapshot: an address the name gains later is not reachable, and
  one it loses stays reachable until the run ends. The lookup is the guard's own, in a mode that
  runs outside the sandbox before the command, reads the one answer a resolver gives with every
  length checked, takes an address only from a record that belongs to the name asked or to an alias
  chain that leads from it, and refuses a truncated or malformed answer, a name that does not resolve
  and an answer to another question; it asks only the resolver given, never `/etc/resolv.conf`. The
  name's owner decides which addresses it leads to, as for a TCP name, so a name that leads to a
  loopback or private address allows datagrams there. A name is mapped in `/etc/hosts` only where the file
  holds none of it yet or exactly the addresses this run resolved, whoever's lines they are, because
  otherwise the command, or the command of another run that pinned the name, could be handed an
  address its own guard denies; the run is refused too where the addresses add up to more rules than
  the guard keeps. A name written in two cases is resolved once. External
  egress in general is still a container started with `--network none`, and resolving needs a
  networked one, so a name in a udp rule assumes the same posture as one in a tcp rule.
- `docker/prune_phase/` runs the discovery phase, which deliberately breaks a build over and
  over: it hides a directory, runs the tests, and concludes from the failure that the
  directory was needed. Its orchestrator therefore starts processes and interprets their
  failures, and its output becomes the allow-list the sandbox later trusts. The discovery
  phase uses Bubblewrap to hide directories; the sandbox an exercise runs in does not.
- The Dockerfiles under `docker/` extend the Artemis test images and compile the C products.
  The run-phase image needs no user namespaces, no added capabilities and no security
  options: Landlock, the connect guard and the timeout are all self-imposed by the
  unprivileged process. The container the grader starts should add `--network none` and
  cgroup limits, which are the outer boundary Phobos cannot set from inside itself.

The four C products, `phobos-landlock-filesystem-and-networksystem`, the connect guard, the
timeout's group lock and the report-only supervisor `phobos-seccomp-filesystem`, are not
committed. They are compiled inside the run-phase image from the source under `core/`, and CI
checks the copies the image ships are position-independent with full RELRO. Where the connect guard binary is missing
the network layer refuses to start rather than run the command without connect supervision, so a
bare checkout with nothing built does not run. The delivery vehicle is the run-phase image,
published multi-arch, so a grader pulls the build for its own architecture.

## Threat model, in one paragraph

Phobos defends the *grading machine* against untrusted student code executed during a test
run. It does not defend the student's own submission from anything, and it is not a general
containment boundary against a determined attacker with local privilege. The allow-list is
derived empirically by the pruning phase, so it is only as tight as the reference exercises
that produced it: a resource no reference exercise touched is hidden, and a resource one of
them touched is permitted for every submission thereafter.

The policy is additive: everything is denied first, and the platform, language and exercise
configurations each only widen the allow-list. An exercise configuration may therefore name a
path or grant a right the base did not, so the configuration files are *trusted input*, on the
same footing as the reference exercises the pruning phase runs. They must be supplied by the
instructor and must never be writable by the code being graded; a submission that could edit
its own exercise configuration could grant itself any access, and that is an integration
requirement Phobos relies on rather than a boundary it enforces.

An Ares 2 security policy given to `--config` grants access exactly as an exercise
configuration does, so the same holds for it: it must come from the instructor's test
repository, never from the student's assignment tree. In an Artemis build a
`security-policy.yaml` usually sits in the test repository's `src/test/resources`, and a
grading script that searched the merged working tree for such a file could pick up a copy the
submission placed there. The values an import depends on are operator input in the same way:
the project root (`--project-root`, or the tail flags' last `--chdir`), which must be the
directory the build tool starts the test JVM in, and the placeholder values a programming
language configuration determines from the environment, the `PATH` and the password database
of the process that runs `phobos.sh`. All of them are fixed before the command is started; a
grading setup that hands `phobos.sh` an environment the submission influenced breaks this.

A path a policy names is resolved through its symbolic links when the specification is built,
and by then the submission is usually in place. A relative path in an Ares 2 policy names a
place inside the project root, which usually holds the submission's checkout, so a symbolic
link the submission commits at any component of that path makes the grant land where the link
points. The same holds for a path in an exercise configuration that lies in the submission's
tree. Grant such a path only where no component of it is the submission's to choose, or build
the specification before the submission is copied in.

## The environment Phobos is started in

A grader may start Phobos with the submission's tree as the current directory, so anything
Phobos looks up relative to that directory before the sandbox exists is the submission's to
choose. Every entry point, `phobos.sh` and each layer started on its own alike, therefore
begins with `clean_startup_environment` (`core/phobos-tools-common/phobos-environment.sh`),
before it runs any program or `cd`:

- **PATH keeps only its absolute entries.** `.`, every other relative directory, an empty entry
  (a leading or trailing colon, or two in a row) and an entry beginning with `~`, which bash
  expands but `execvp` takes as a directory in the current one, are removed. Absolute entries
  are kept as written, whether or not they exist, since they name the same place from every
  directory, and none is ever added: a PATH with no absolute entry is refused with
  `PHB-ERUNTIME`, because an empty PATH is searched as the current directory. The command is
  given the cleaned PATH too, so a command that relied on `.` must be named by its path, as in
  `./gradlew test`. Inside the sandbox a relative entry could reach nothing Landlock denies, but
  one PATH for the whole run means no helper of Phobos can meet the original by mistake. Where
  the environment has no PATH at all, bash invents one for its own lookups, and some builds end
  it in `.`: that one is cleaned too, but stays unexported, so the command is given no PATH, as
  before.
- **CDPATH is unset**, so the `cd` an entry point makes to find its own directory goes where its
  argument says, and the command does not inherit it.
- **TMPDIR and the C library's own path variables keep only what is absolute.** `TMPDIR` is unset when it
  is not absolute, so no program Phobos or the command starts makes its temporary files beneath
  the current directory. The relative entries of `GCONV_PATH` (where the C library loads
  character-set modules from, as code), `LOCPATH` and `NLSPATH` are removed, and `HOSTALIASES`
  and `TZDIR` are unset when they are not absolute, since every program Phobos starts would
  resolve them against the current directory. Absolute values are kept.

Each entry point says on stderr what it removed from these, CDPATH and an invented PATH aside.

The interpreter is not looked up either. Every script under `core/` begins with `#!/bin/bash`, so
an entry point started as a program runs the system's bash whatever the caller's PATH holds, and
so does every layer it starts afterwards by its absolute path. With `#!/usr/bin/env bash`, `env`
would find `bash` through the caller's PATH before the script ran a line, and a relative entry
ahead of bash's own directory would run a `bash` from the current directory instead of Phobos.
The run-phase image, and every image built on it, has bash at `/bin/bash`.

Some of the same class happens before a script's first line, so no script can undo it, and these
are integration requirements on the grader:

- **Start Phobos without `BASH_ENV`.** Bash sources the file it names before the first line of
  every non-interactive script, Phobos's own among them, and resolves a relative name against
  the current directory. `ENV` is read only by interactive shells and does not reach Phobos.
- **Start Phobos without `LD_LIBRARY_PATH`, `LD_PRELOAD` and `LD_AUDIT`.** The dynamic loader
  reads them when every program starts, the bash running `phobos.sh` included, and searches a
  relative or empty `LD_LIBRARY_PATH` entry in the current directory. Removing them inside the
  script would come after that bash had already loaded its libraries, so it is not done. For
  the same reason the bash running `phobos.sh` may already have read locale data or loaded
  character-set modules through a relative `LOCPATH` or `GCONV_PATH` before they are cleaned for
  everything after it.

The simplest way to meet both is a minimal environment of absolute values:
`env -i PATH=/usr/local/bin:/usr/bin:/bin /var/tmp/opt/core/phobos.sh --config exercise.cfg -- ./gradlew test`,
adding back only what the command needs.

## A run's own files are out of the command's reach

Every temporary file Phobos makes for a run, the port lists the network layer builds its Landlock
rules from among them, lives in the run's specification directory, most of them in its scratch
subdirectory. The policy program refuses to place a specification directory it builds beneath a
write path; one handed straight to a layer is the caller's to place. Each layer that makes such
files sets the scratch directory itself, rather than taking `PHOBOS_SCRATCH` or `TMPDIR` from its
environment, and a helper called without one refuses with `PHB-ERUNTIME` rather than fall back to
`TMPDIR`, or to `/tmp`, which the shipped policies make writable, so the command of a concurrent
run in the same container could see such a file, and as the same user replace it, while another
run still reads its rules from it.

## Inbound filtering assumes a networked container, and is defence in depth, not a boundary

An `[accept]` rule fronts a student's TCP listener with an inbound HAProxy that admits only the
source addresses the rule names, forwarding an admitted connection to the student's backend port.
It is a defence-in-depth layer for deployments that expose a student's server, not a boundary of
the same class as the filesystem or egress layers, and enabling it changes the run's posture:

- **It removes `--network none`.** An external client cannot reach a `--network none` container,
  so an `[accept]` rule only works where the container has a real network. Turning it on therefore
  gives up the hard no-network backstop the rest of the sandbox leans on; egress is then contained
  only by the connect guard, the Landlock TCP-port rules, the egress broker when it is on and
  whatever the integrator firewalls, not by the absence of a network.
- **Phobos hard-locks the listening port, not its reachability.** With `[bind]` naming only the
  backend port, Landlock refuses the student a listener on any other port, the public port
  included, in the kernel and against raw system calls. But Landlock's bind right is per port, not
  per address, so the student may bind the backend port on all interfaces; that the backend is
  reachable *only* through the filter is provided by the container's network isolation, not by
  Phobos. That isolation must be concrete: a dedicated network with inter-container communication
  disabled, only the public port published, no other or UDP port exposed. `[accept]` covers TCP
  only.
- **The connect guard closes the listen that never binds.** Landlock judges `bind()`, but the
  kernel also gives a socket that was never bound a port of its own choosing when it calls
  `listen()`, and Landlock has no hook for that. The connect guard therefore traps `listen()` and
  runs it itself, only on a socket it created for the command, and refuses a socket that is
  unbound unless it is started with `--allow-ephemeral-listen`, which the network layer sets when
  a `[bind]` row names port 0, because that row already grants the port the kernel would choose.
  A swap of another socket under the descriptor cannot create a listener, because the guard never
  lets the kernel run the command's own `listen()`. With `--no-networksystem-restriction` the
  guard is absent and so is this.
- **The connect guard makes every datagram connect and send itself.** A destination behind a
  pointer cannot be checked and then left to the kernel: re-running the call reads the pointer
  again, and a second thread of the command can show the check one address and the kernel
  another. Measured against a destination that thread rewrites, that sent about one datagram in six
  to an address the allow-list did not name. So the guard copies the address, the data and the
  lengths out of the command once, checks the copies, and sends from them on its own descriptor
  for the very socket the command holds, never letting the call continue. The datagram `connect()`
  is made the same way, which is why the command's own address-less `send()` then reaches a peer
  the guard vetted, and a `sendto()` without an address is the one send the filter lets through.
  The guard enforces the destination port and the source port itself, because it runs outside
  Landlock: a connect or send on a socket that was never bound is refused unless the policy grants
  an ephemeral UDP bind (`--allow-ephemeral-udp-bind`, set by the network layer for a udp `[bind]`
  row of port 0 or any udp `[connect]` rule), since the kernel would give it a source port nobody
  judged. This costs, and the costs are the price of closing the race rather than defects:
  a datagram socket stays held by the guard after the command closes it until the table of 512
  held sockets evicts it, so a port it was bound to stays taken and datagrams queued for it stay in
  memory; a send on a socket the guard does not hold (inherited, received over a descriptor, or
  evicted) is refused; `sendmsg` and `sendmmsg` are refused on every socket the guard does not hold,
  which includes TCP and UNIX sockets, because a second thread could swap a datagram socket
  under such a descriptor and name a destination; a send with ancillary data, a flag the guard
  cannot pass on (`MSG_ZEROCOPY`, `MSG_OOB`), a datagram beyond 64 KiB and a `sendto` or
  `sendmsg` with a UNIX address are refused; and a blocking socket that cannot take a datagram is
  waited on for a second at most before the answer is `EAGAIN`. The guard serves one notification
  at a time, so a slow socket delays every other call of the command by that second at most.
  `tests/integration/seccomp_networksystem.sh` measures all four calls against the rewritten
  destination, with a control without the guard that reaches it.
- **Bind is closed unless a `[bind]` row opens it, as far as the kernel can close it.** The network
  layer always applies a network-only Landlock ruleset that handles TCP and UDP bind with nothing
  granted, so a run with no `[bind]` rule, or given no `--config`, binds and listens on nothing.
  Port 0 grants only a port the kernel chooses. The shipped Java policy carries `allow 0` and
  `allow 0 udp` for Gradle, so a submission under it can still take a kernel-chosen port, on every
  interface, but cannot name one; because policies are additive, an exercise that names only
  `allow 8080` gets port 0 from that base as well. A kernel below Landlock version 4 (TCP) or 10
  (UDP) cannot close the direction: the enforcer says so on every run and leaves it open, and the
  container's network isolation is the only boundary there. `--minimum-landlock-version` in the tail
  flags turns that into a refusal. At the time of writing none of the kernels the project's CI
  and local runs use offers version 10, so the UDP half has been exercised against a recording of the
  kernel's calls only.
- **A source address is weak authentication.** It resists spoofing only for an established
  handshake, and NAT and shared egress addresses make it coarse. Treat it as a filter, not an
  identity.

Enabling `[accept]` is deliberately not silent: a run with one present says loudly that it assumes
this networked posture.

## Scope

A report is in scope when Phobos fails at what it claims to do, or when it causes harm nobody
asked for. Concretely:

- a submission reaching a file, or a TCP or (on Landlock version 10) UDP port Landlock was given,
  that the active allow-list does not permit
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
