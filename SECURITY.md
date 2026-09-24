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
- `core/phobos-seccomp-networksystem.c` is the connect guard. When the network layer is on it
  supervises every `connect()` with a seccomp user-notification and makes an allowed
  connection itself from outside the sandboxed process, so for `connect` it is a boundary a
  raw system call cannot step around, enforcing the `[connect]` allow-list by host and port.
  It reads the destination address of the connect, so it holds a rule that names an IP literal
  (and the name `localhost`) to that exact address, a rule that names an IP range to that
  network, and a rule that names a DNS hostname it cannot tie to an address there to its port
  alone. Such a hostname rule's host is enforced by the egress broker, an HAProxy the network
  layer starts automatically for such a rule and that checks the TLS host name the guard cannot
  see; the network layer refuses an exact-name rule when no resolver is given, so an instructor
  who needs a rotating, CDN-backed host either gives a resolver or names its address range rather
  than its name. Since seccomp stops the call before the kernel path where Landlock would check the
  port, the guard connects outside Landlock and so is the whole connect boundary where it runs;
  Landlock's `--connect-tcp` ports remain a second, kernel-enforced expression of the same
  ports. A `connect` of a family the guard does not carry (a UNIX-domain socket) is refused
  rather than made outside the Landlock view the command is held to. A `[connect]`/`[bind]` rule may
  carry a `udp` transport marker: the guard enforces it for the UDP transport apart from TCP, and
  Landlock's `--connect-udp`/`--bind-udp` (the version-10 UDP rights) are its second, kernel-enforced
  expression. UDP needs Landlock version 10, so a udp rule is refused on an older kernel rather than
  left unenforced. Host-level UDP egress beyond the allow-list (a udp rule may name only an address
  or a range, not a host name), and external egress in general, are still a container started with
  `--network none`.
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

The three C products, `phobos-landlock-filesystem-and-networksystem`, the connect guard and the timeout's group lock, are not
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
