---
title: "What does Phobos protect against"
sidebar_position: 2
description: "The four boundaries Phobos enforces, and what each one refuses."
---

:::tip[Simple Story]
Four things stand between the program and the machine: the drawers that do not open, the
telephone that reaches three numbers, the clock on the wall, and the size of the bench.

Every one of them was put there by the operating system before the program arrived, and none of
them can be talked round.
:::

Phobos protects the machine that runs a command against that command. Each of the four layers
refuses a different class of reach, and each refuses it from outside the process rather than
from inside it.

## The filesystem

`phobos-landlock` builds a Landlock ruleset from the policy and calls `landlock_restrict_self`,
after which the process and everything it starts can only lose access, never regain it. A path
the policy does not name is refused with `EACCES`, and a path it names is granted exactly the
rights the policy asked for, one right at a time.

What that refuses:

- reading a file or listing a directory the policy never named
- writing into, or truncating, a file on a path granted only read
- executing a program from a tree granted only read
- creating a file, a directory, a socket, a named pipe or a symbolic link where the policy
  granted no such right
- deleting anything on a path granted no delete right
- renaming or moving across directories, unless the policy granted the REFER right
- `ioctl` on a character or block device on a path granted no `ioctl` right
- creating a device node, which no policy can grant at all

From Landlock version 6 the ruleset carries scoping, so the command cannot signal a process
outside the sandbox and cannot reach an abstract UNIX socket outside it.

## The network

Landlock enforces ports, and it knows nothing about hosts. Phobos therefore expresses one
allow-list in two places, with a third for host names:

- **The connect guard** supervises every `connect()` with a seccomp user-notification and, for
  a stream, makes the allowed connection itself from outside the process, so the command never
  runs a stream `connect()` of its own. Where it runs it is the whole connect boundary, host
  and port, and a raw system call cannot step around it. It refuses a raw, packet or ICMP
  socket before the socket exists, judges a datagram that carries its own destination the way
  it judges a connect, refuses `io_uring` as a second syscall interface that would reach
  `connect` unseen, and refuses `setsid` and `setpgid`. A datagram `connect()` sets a default
  peer alone, so the guard checks it and lets it through; the checked send that follows is the
  boundary there.
- **Landlock port rules** are the kernel-enforced second expression of the same ports, through
  `--connect-tcp` and `--bind-tcp`, and, on a version 10 kernel, `--connect-udp` and
  `--bind-udp`.
- **The egress broker** enforces a rule that names a host. The network layer starts it
  automatically for such a rule. It reads the Transport Layer Security (TLS) host name from the
  ClientHello, which the guard cannot see, and for an exact name it resolves the name itself and
  connects only to that address.

A listener is bounded from the other direction: `[bind]` names the local ports the command may
listen on, and an `[accept]` rule fronts one of them with an inbound HAProxy that admits only
the source addresses the rule names.

## The clock

The timeout layer runs the rest of the chain under GNU `timeout`, which puts the command in its
own process group and signals the whole group on expiry, escalating to `SIGKILL` for a command
that ignores `SIGTERM`. Underneath it sits a seccomp filter that refuses `setsid` and
`setpgid`, so nothing under the timeout can leave the group the kill targets and outlive its
limit.

A run is reported as a timeout only where GNU `timeout` says so **and** the run lasted at least
its limit, so a command's own exit status 124, or a `SIGKILL` from the out-of-memory killer,
passes through unchanged rather than being relabelled.

## The size of the bench

The resource layer sets rlimits for the memory, the number of processes, the number of open
files, the largest file and the processor time the policy named. They are set as the last step
before Landlock, so they bind the command and everything it starts, and none of the helpers
Phobos runs beside it. A helper that met the command's file-size limit would otherwise take the
command's output with it.

## What holds all four together

Every layer fails closed. A missing connect guard, a missing process-group lock, an
unenforceable policy, a kernel too old for a right the policy named: each ends the run with a
message and a non-zero status rather than running the command with that layer quietly absent.
With no base policy present at all, Phobos refuses to run rather than run the command
unprotected.

## Further reading

- [What does Phobos not protect against](what-does-phobos-not-protect-against.md) — where the
  boundary ends
- [Landlock](/contributor/technologies/landlock) — the kernel mechanism behind the filesystem
  and port rules
- [Seccomp](/contributor/technologies/seccomp) — the mechanism behind the connect guard and the
  process-group lock
