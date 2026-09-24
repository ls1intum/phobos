---
title: "Exposing a listener"
sidebar_position: 5
description: "Letting a command serve on a local port, and fronting that port with a source filter."
---

:::tip[Simple Story]
The work answers the door.

Phobos decides which socket in the wall the work may plug into, and puts a doorkeeper in front
of it. Who can reach the door at all is the building's business.
:::

## The situation

The command starts a server that something outside has to reach: a web service under test, a
protocol implementation, a task that is graded by talking to it.

## The policy fragment

```ini title="exercise.cfg"
[bind]
allow 8080

[accept]
expose 18080 to 8080 from 198.51.100.0/24
```

Two ports, with different jobs. `8080` is the command's own listening port, and Landlock
refuses it a listener on any other. `18080` is the port the container exposes, which the
inbound filter binds and which the command may not bind itself.

## What this still forbids

- a listener on any port `[bind]` does not name, refused in the kernel and against raw system
  calls
- an inbound connection from any source outside `198.51.100.0/24`
- an outbound connection, unless `[connect]` names one
- a datagram listener, which needs `allow 5353 udp` and Landlock version 10

## The tempting wrong version

```ini title="wrong.cfg"
[bind]
allow 8080

[accept]
expose 8080 to 8080 from 198.51.100.0/24
```

Fronting a port the command may itself bind lets it take that port before the filter starts and
receive unfiltered connections. Phobos refuses this with `PHB-EPOLICY`.

Three more are refused for related reasons: a public port below 1024, which cannot be bound
without a capability the run does not have; a backend port `[bind]` does not name, which would
leave the filter forwarding to a listener that never comes up; and two rules fronting one
public port with different backends.

A fourth passes and serves nobody:

```ini title="also-wrong.cfg"
[bind]
allow 8080

[accept]
expose 18080 to 8080 from
```

A rule with no source admits nobody. That is the fail-closed direction, and Phobos warns that
the service is unreachable rather than failing. The literal word `from` stays even where no
source follows it; a line without it is not an `[accept]` rule at all.

## Notes

:::warning[An `[accept]` rule changes the run's posture]
It removes `--network none`, because an external client cannot reach a container that has no
network. It locks the listening port, not its reachability: Landlock's bind right is per port
rather than per address, so the command may bind its backend port on every interface. That the
backend is reachable only through the filter comes from the container's network isolation, and
that isolation has to be concrete: a dedicated network with inter-container communication
disabled, only the public port published, nothing else exposed. A source address is a filter,
never an identity.
:::

- A `[bind]` rule takes a bare port. A rule that names an address is refused, because Landlock
  cannot narrow a bind to a local address.
- With `--no-networksystem-restriction`, the `[accept]` rule starts no filter and the port is
  not locked either. `phobos.sh` reports that rather than leaving it silent.
