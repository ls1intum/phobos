---
title: "[bind]"
sidebar_position: 10
description: "The local ports a command may listen on, one bare port per line."
---

:::tip[Simple Story]
The room has a few sockets in the wall, and the work may plug into those and no others.

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

A bare port is the only accepted target, and the transport marker defaults to `tcp`.

```ini
[bind]
allow 8080
allow 5353 udp
```

## Why a rule may not name an address

Landlock enforces a bind by port and cannot narrow it to a local address. A rule that names an
address is therefore refused with `PHB-EPOLICY` rather than accepted and half-enforced. A
listener's reachability from outside is governed by [`[accept]`](accept.md) and by the
container's network isolation, never by the address it bound.

## What enforces it

Each port becomes one Landlock rule, `--bind-tcp` or `--bind-udp`, applied on the network
layer's own ruleset. That is the whole of the enforcement for this section: the connect guard
does not judge a bind.

Several rules that share a port and a transport collapse into one flag. A port outside 1 to
65535 ends the run with `PHB-EPOLICY`.

## The ephemeral source port

Where a policy names both a `udp` bind and a `udp` connect rule, Phobos adds `--bind-udp 0`, a
rule for any local port. The kernel auto-binds an ephemeral source port for an outgoing
datagram, and once `BIND_UDP` is handled that auto-bind is itself gated by it, so an allowed
send would otherwise be denied its own source port. The extra rule is added in that one case
alone, so a stream-only policy gains no bind capability it did not ask for.

## Notes

**A datagram bind needs Landlock version 10**, the same as a datagram connect.

**Binding is not accepting.** A port named here may be listened on. Whether anything outside
can reach it is the container's question, and [`[accept]`](accept.md) is the filter in front
of it.

## Further reading

- [`[accept]`](accept.md) — fronting a listener with a source filter
- [Exposing a listener](/user/policy-cookbook/exposing-a-listener) — the recipe
