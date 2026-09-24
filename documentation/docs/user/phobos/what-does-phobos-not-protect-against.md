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

## The container supplies the hard caps

The resource layer sets rlimits, which are self-imposed and therefore hold inside an ordinary
unprivileged container. They are an in-process line of defence, not the hard cap a machine
needs against a determined command. A fork bomb filling the process table and a run filling the
disk are stopped by cgroup limits the container is started with (`--memory`, `--pids-limit`,
`--cpus`, and a size-bounded `--tmpfs` for scratch). Phobos cannot set those for itself and
does not assume they are set.

## Network isolation is not provided

Phobos filters outbound stream `connect()` from outside the process, at the seccomp and
Landlock boundaries, and interposes no library call inside the process. Three things sit
outside that:

- **Host-level datagram egress.** A `udp` rule in `[connect]` may name an address, a range or
  `*`, or the name `localhost`, never a host name that has to be resolved. Host enforcement
  rests on the Transport Layer Security (TLS) host name, which is a stream concept, so datagram
  traffic beyond the allow-list is governed by the container.
- **Inbound connections no `[accept]` rule fronts.** The inbound filter covers the ports it is
  given, on the Transmission Control Protocol only.
- **Everything on a kernel below Landlock version 10**, where the UDP rights do not exist. A
  `udp` rule is refused on such a kernel rather than left unenforced, so the run stops instead
  of running with an unenforced rule.

A deployment that wants no network at all starts the container with `--network none`, under
which only loopback exists. A deployment that needs `[accept]` gives that up and has to provide
the isolation itself.

## Inbound filtering is defence in depth, not a boundary

An `[accept]` rule fronts a listener with an inbound HAProxy that admits only the source
addresses the rule names. Three limits come with it:

- **It removes `--network none`.** An external client cannot reach a container that has no
  network, so the rule only works where the container has a real one.
- **Phobos locks the listening port, not its reachability.** Landlock refuses the command a
  listener on any port `[bind]` does not name, in the kernel and against raw system calls. The
  bind right is per port rather than per address, though, so the command may bind its backend
  port on every interface. That the backend is reachable *only* through the filter comes from
  the container's network isolation.
- **A source address is weak authentication.** It resists spoofing only for an established
  handshake, and network address translation makes it coarse. Treat it as a filter, never as an
  identity.

## Attacks inside a language runtime

A command that stays inside its own process and never asks the kernel for anything is invisible
to Phobos. Reflection, unsafe memory access, deserialisation and class loading inside a
Java Virtual Machine (JVM) never reach the operating system, so no operating-system sandbox sees
them. That layer is [Ares 2](https://github.com/ls1intum/Ares2), which instruments the runtime
itself. A grading host is protected where Ares, Phobos and the container are all in place.

## A right the running kernel does not know

Landlock grew one release at a time. A right the running kernel does not know is not merely
ungranted, it is not handled at all, so it is free on every path including the ones the policy
calls read-only. `phobos-landlock` reports every such gap before the run rather than leaving it
to be discovered, and `--minimum-landlock-version` refuses a kernel too old for the guarantee
you need. The table on the [Landlock](/contributor/technologies/landlock) page says which
version brought which right.

## Two things a path set cannot express

- **Landlock grants a whole subtree and cannot carve an exception inside it.** A path is either
  granted, with everything beneath it, or not granted.
- **A path the policy does not name stays visible.** Landlock withholds access rather than
  building a new view of the filesystem, so the name of a denied path can still be seen. The
  discovery phase hides a directory; a protected run refuses it.

## Further reading

- [SECURITY.md](https://github.com/ls1intum/phobos/blob/main/SECURITY.md) — the threat model
  and what is in scope for a report
- [What does Phobos protect against](what-does-phobos-protect-against.md) — the other direction
- [How the discovery phase decides](/contributor/pruning) — what the prune phase measures, and
  where it errs
