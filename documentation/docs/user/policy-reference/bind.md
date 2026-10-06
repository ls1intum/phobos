---
title: "[bind]"
sidebar_position: 10
description: "The local ports a command may listen on, one bare port per line."
---

:::tip[Simple Story]
The room has no sockets in the wall unless the policy puts one there, and the work may plug
into those and no others.

Which of them can be reached from the corridor is a different question, settled by the
building rather than by the socket.
:::

## Position in the example policy file

The section documented on this page is marked in red. Every page in this section shows the same
example file, so reading them in order walks it from top to bottom.

```ini title="exercise.cfg"
# Every section this reference documents, gathered in one file so that each page can
# point at its own. A real policy names only what its command needs.

[read]
/srv/reference-data
/opt/toolchain

[execute]
/opt/toolchain

[write]
/var/tmp/workspace

[create]
/var/tmp/workspace

[delete]
/var/tmp/workspace

[create-ipc]
/var/tmp/workspace/run

[create-symlink]
/var/tmp/workspace/build

[restructure]
/var/tmp/workspace

[connect]
allow 192.0.2.10:443
allow repo.example.org:443
allow 203.0.113.53:53 udp

# policy-focus-start
[bind]
allow 8080
allow 5353 udp
# policy-focus-end

[accept]
expose 18080 to 8080 from 198.51.100.0/24

[limits]
timeout=120
mem_mb=2048
nproc=256
nofile=1024
fsize_mb=512
cpu=100
```

That file is a catalogue rather than a working configuration. Three of its entries change what
a run needs, and [the Policy Reference index](index.md) says which.

## Syntax

```
allow <port> [udp|tcp]
```

A bare port is the only accepted target, and the transport marker defaults to `tcp`. The port is
a number from 1 to 65535, or `0`, which means a port the kernel chooses.

```ini
[bind]
allow 8080
allow 5353 udp
allow 0
```

## Why a rule may not name an address

Landlock enforces a bind by port and cannot narrow it to a local address. A rule that names an
address is therefore refused with `PHB-EPOLICY` rather than accepted and half-enforced. A
listener's reachability from outside is governed by [`[accept]`](accept.md) and by the
container's network isolation, never by the address it bound.

## Bind is closed unless a row opens it

A run with no `[bind]` rule cannot bind or listen on any port, and neither can a run given no
`--config`. The network layer applies its Landlock ruleset on every run with `--close-bind`,
which hands the kernel both bind directions with nothing granted. Only a `[bind]` row opens a
port.

## What enforces it

Each port becomes one Landlock rule, `--bind-tcp` or `--bind-udp`, applied on the network
layer's own ruleset. Several rules that share a port and a transport collapse into one flag. A
port outside 0 to 65535 ends the run with `PHB-EPOLICY`, and so does `00`.

**Port 0 grants a port the kernel chooses, and never a port the command names.** It becomes
`--ephemeral-bind-tcp` or `--ephemeral-bind-udp`. A server that takes whatever port it is given,
as Gradle and its test workers do, needs it, and the shipped Java policy carries `allow 0` and
`allow 0 udp`. An explicit port does not open the kernel's own choice, and the other way round.

The connect guard closes the one route Landlock cannot judge. A socket that was never bound gets
a port of the kernel's choosing when it calls `listen()`, with no `bind()` at all. The guard
traps `listen()` and runs it itself, on a socket it created, and refuses an unbound socket
unless a tcp `[bind]` row names port 0, because that row already grants the same port.

## The ephemeral source port

A `udp` connect rule brings the ephemeral UDP grant with it. The kernel auto-binds an ephemeral
source port for an outgoing datagram, and now that UDP bind is always handled, that auto-bind
is gated by it, so an allowed send would otherwise be denied its own source port. A policy with
no `udp` connect rule gains nothing.

## Notes

**A datagram bind on a port other than 0 needs Landlock version 10**, the same as a datagram
connect rule that names a port. Below it the enforcer ends the run with exit status 125. A `udp`
loopback rule with no port in `[connect]` lifts that for a connect rule only, never for a
`[bind]` row.

**A kernel too old to close bind leaves it open and says so.** Below Landlock version 4 for TCP
and version 10 for UDP, the enforcer prints a warning on every run, and the container's network
isolation is the only boundary there. `--minimum-landlock-version` in the tail flags turns the
warning into a refusal. An explicit port rule still refuses a kernel that cannot handle it,
where a port 0 grant never does.

**Policies are additive.** An exercise that names only `allow 8080` still gets port 0 from the
shipped Java policy, so it can still take a port the kernel chooses, on every interface.

**The shipped Python policy grants no bind.** A Python exercise that starts a server needs
`allow 0` of its own.

**Binding is not accepting.** A port named here may be listened on. Whether anything outside
can reach it is the container's question, and [`[accept]`](accept.md) is the filter in front
of it.

## Further reading

- [`[accept]`](accept.md) — fronting a listener with a source filter
- [Exposing a listener](/user/policy-cookbook/exposing-a-listener) — the recipe
