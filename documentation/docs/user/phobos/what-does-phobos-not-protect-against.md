---
title: "What does Phobos not protect against"
sidebar_position: 3
description: "Where the Phobos boundary ends, and what the container and the deployment still have to do."
---

:::tip[Simple Story]
The room has walls, a door and a clock. It has no roof, and the building around it is somebody
else's job.

Phobos says plainly which parts it holds, so that nobody mistakes the remaining work for work
that has been done.
:::

Phobos defends the machine that runs a command against that command. It is not a general
containment boundary against an attacker who already holds local privilege, and several things
that look like its job belong to the layer around it. Each of the following is deliberate,
stated here rather than discovered later.

## The allow-list is only as tight as the runs that produced it

The discovery phase derives the allow-list empirically. A resource no reference run touched is
hidden; a resource one of them touched is permitted for every run thereafter. Phobos cannot
know whether a directory was needed for a good reason.

Two consequences follow. A policy pruned from a narrow reference workload refuses a legitimate
run that needed one more path, and a policy pruned from a broad one permits more than any
single run needs. Reading a pruned policy before trusting it is therefore part of the workflow
rather than an optional extra: [How the discovery phase decides](/contributor/pruning) sets out
what the phase measures and where it errs.

## The configuration is trusted input

The policy model is additive by design. Everything is denied first, and the platform, language
and task configurations each only widen the allow-list, which is what lets a task configuration
name a path the base did not.

A configuration file must therefore never be writable by the code it governs. A command that
could edit its own configuration could grant itself any access. That is an integration
requirement Phobos relies on rather than a boundary it enforces. Phobos checks one related
thing for you: the run's specification directory must lie outside every write path, and a
policy that would put it inside one is refused.

## What acts before the first line of Phobos

Every entry point removes the relative entries of `PATH` and of the C library's search
variables before it runs anything, so no program it looks up is found in the current
directory. The interpreter is not looked up through `PATH` either: every script under `protecter/src/`
begins with `#!/bin/bash`. Two things still take effect before a script's first line, and no
script can undo them. Keeping them out is the grader's job:

- **`BASH_ENV`.** Bash sources the file it names before the first line of every non-interactive
  script, and resolves a relative name against the current directory.
- **`LD_LIBRARY_PATH`, `LD_PRELOAD` and `LD_AUDIT`.** The dynamic loader reads them when every
  program starts, the `bash` running `phobos.sh` included. That same `bash` can already have read
  a relative `LOCPATH` or `GCONV_PATH` before Phobos cleans them for everything after it.

SECURITY.md states these as integration requirements, with a minimal `env -i` invocation that
meets them.

## The container supplies the hard caps

The resource layer sets rlimits, which are self-imposed and therefore hold inside an ordinary
unprivileged container. They are an in-process line of defence, not the hard cap a machine
needs against a determined command. A fork bomb filling the process table and a run filling the
disk are stopped by cgroup limits the container is started with (`--memory`, `--pids-limit`,
`--cpus`, and a size-bounded `--tmpfs` for scratch). Phobos cannot set those for itself and
does not assume they are set.

## Network isolation is not provided

Phobos filters outbound stream `connect()` and every datagram connect and send from outside the
process, at the seccomp and Landlock boundaries, and interposes no library call inside the
process. Three things sit outside that:

- **Host-level datagram egress beyond the allow-list.** A `udp` rule in `[connect]` that names a
  host is held to the addresses the name had when the run began, because a datagram carries no
  Transport Layer Security (TLS) host name to check. An address the name gains later is not
  reachable through that rule, and the container's isolation is the boundary beyond it.
- **Inbound connections no `[accept]` rule fronts.** The inbound filter covers the ports it is
  given, on the Transmission Control Protocol only.
- **UDP bind on a kernel below Landlock version 10.** The guard still holds UDP connect and send
  by host and port, but the kernel cannot close UDP bind there, so the enforcer warns and the
  bind stays open. A `udp` `[connect]` or `[bind]` rule that names a port is refused on such a
  kernel, with exit status 125. The exceptions are a `udp` `[connect]` rule beside a `udp`
  loopback rule with no port, which the guard alone holds, and a `udp` `[bind]` row of port 0.

A deployment that wants no network at all starts the container with `--network none`, under
which only loopback exists. A deployment that needs `[accept]` gives that up and has to provide
the isolation itself.

## Inbound filtering is defence in depth, not a boundary

An `[accept]` rule fronts a listener with an inbound HAProxy that admits only the source
addresses the rule names. Three limits come with it:

- **It removes `--network none`.** An external client cannot reach a container that has no
  network, so the rule only works where the container has a real one.
- **Phobos locks the listening port, not its reachability.** Landlock refuses the command a
  listener on any port `[bind]` does not name, in the kernel and against raw system calls, and
  the connect guard refuses a `listen()` on a socket that was never bound. The
  bind right is per port rather than per address, though, so the command may bind its backend
  port on every interface. That the backend is reachable *only* through the filter comes from
  the container's network isolation.
- **A source address is weak authentication.** It resists spoofing only for an established
  handshake, and network address translation makes it coarse. Treat it as a filter, never as an
  identity.

## What it costs that the guard sends the datagrams itself

The connect guard makes every datagram `connect()` and every `sendto()`, `sendmsg()` and
`sendmmsg()` that names a destination on a socket it created and still holds, from copies it took
of the address and the data once. A `sendto()` with no address is the one send it lets through
untouched, since it is the send of a connected socket, whose peer the guard vetted when it made the
connect; on a socket inherited from outside, already connected, it goes to the peer chosen before
the sandbox. The copying closes the race in which a second thread rewrote the address between
the check and the kernel's own read, which sent about one datagram in six to an address the
allow-list never named. It has costs, and they are the price of closing it:

- A datagram socket stays held by the guard after the command closes it, until the table of 512
  held sockets, which the sockets that can listen share, is full and this one is the least
  recently used. A port it was bound to stays taken, and datagrams queued for it stay in memory.
- A send on a socket the guard did not create, an inherited one, one received over a descriptor
  or one it has evicted, is refused.
- `sendmsg` and `sendmmsg` are refused on every socket that is not a datagram socket the guard
  still holds, TCP and UNIX sockets included, because a second thread could swap a datagram socket
  under such a descriptor.
- A send with ancillary data, a flag the guard cannot pass on (`MSG_ZEROCOPY`, `MSG_OOB`), a
  datagram of more than 65,535 bytes, a message of more than 1,024 segments, and a `sendto` or
  `sendmsg` with a UNIX address are refused.
- A blocking socket that cannot take a datagram is waited on for one second at most per message,
  then answered `EAGAIN`. The guard serves one call at a time, and a `sendmmsg` of many messages
  can wait once for each, so a slow socket delays every other call of the command meanwhile.
- A connect or send on a socket that was never bound is refused unless the policy grants an
  ephemeral UDP bind.

## A host name in a `udp` rule is a snapshot

The addresses of a name in a `udp` rule are the ones it had when the run began, and the name's
owner decides which they are, as for a stream name. A name that leads to a loopback or private
address allows datagrams there. An address the name gains later is not reachable, and one it
loses stays reachable until the run ends.

## A kernel too old to close bind leaves it open

Landlock can close TCP bind from version 4 and UDP bind from version 10. Below that, the enforcer
warns on every run and the bind stays open, so the container's network isolation is the only
boundary there. `--minimum-landlock-version` in the tail flags turns the warning into a refusal.
At the time of writing none of the kernels this project's tests run on offers version 10, so the
UDP half has been exercised against a recording of the kernel's calls only.

## Attacks inside a language runtime

A command that stays inside its own process and never asks the kernel for anything is invisible
to Phobos. Reflection, unsafe memory access, deserialisation and class loading inside a
Java Virtual Machine (JVM) never reach the operating system, so no operating-system sandbox sees
them. That layer is [Ares 2](https://github.com/ls1intum/Ares2), which instruments the runtime
itself. A grading host is protected where Ares, Phobos and the container are all in place.

## A right the running kernel does not know

Landlock grew one release at a time. A right the running kernel does not know is not merely
ungranted, it is not handled at all, so it is free on every path including the ones the policy
calls read-only. `phobos-landlock-filesystem-and-networksystem` reports the gaps in `TRUNCATE`, ioctl, scoping and bind closing before the run, and notes a missing
`REFER`. It does not report a kernel below version 9, where connecting to a pathname UNIX socket
outside the sandbox is not restricted, and `--minimum-landlock-version` refuses a kernel too old for the guarantee
you need. The table on the [Landlock](/contributor/technologies/landlock) page says which
version brought which right.

## Two things a path set cannot express

- **Landlock grants a whole subtree and cannot carve an exception inside it.** A path is either
  granted, with everything beneath it, or not granted.
- **A path the policy does not name stays visible.** Landlock withholds access rather than
  building a new view of the filesystem, so the name of a denied path can still be seen. The
  discovery phase hides a directory; a protected run refuses it.

## Further reading

- [SECURITY.md](https://github.com/ls1intum/phobos/blob/main/SECURITY.md): the threat model
  and what is in scope for a report
- [What does Phobos protect against](what-does-phobos-protect-against.md): the other direction
- [How the discovery phase decides](/contributor/pruning): what the prune phase measures, and
  where it errs
