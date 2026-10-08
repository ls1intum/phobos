---
title: "phobos-networksystem.sh"
sidebar_position: 3
description: "The network layer: the connect guard, the egress broker, the inbound filter and the Landlock port rules."
---

:::tip[Simple Story]
The telephone on the bench reaches three numbers.

It is not the handset that enforces that. Somebody outside the room places every call for you,
checks the number first, and hands back the line once it is connected.
:::

The network layer owns the whole network restriction: the connect guard that supervises
outbound connections, the egress broker that enforces a host name, the inbound filter that
fronts a listener, and the Landlock port rules that express the same ports in the kernel.

## Running it on its own

```bash
${PHOBOS_HOME}/phobos-networksystem.sh --config exercise.cfg -- curl https://example.org
```

| Option | What it is for |
| --- | --- |
| `--config <file>` | A configuration to build the specification from. Repeatable. |
| `--spec-parent <dir>` | Where the specification directory is made. The default is `/var/tmp`. |
| `--tail-flags-file <file>` | The tail flags file to apply. |
| `--connect-guard-bin <path>` | The connect guard program to use. |
| `--haproxy-bin <path>` | The HAProxy program the broker and the inbound filter run as. |
| `--resolver <ip[:port]>` | The Domain Name System (DNS) resolver the broker resolves an exact host name through, and the one a `udp` host name is resolved through once at the start. |
| `--landlock-bin <path>` | The `phobos-landlock-filesystem-and-networksystem` program that applies the port rules. |
| `--debug` | Report what the layer builds and runs. |

## The connect guard

The guard is the first thing the layer puts in front of the rest of the chain. It forks: the
child installs a seccomp filter and becomes the rest of the chain, and the parent stays beside
it as a supervisor that is never restricted. Every `connect()` the command makes is trapped to
the supervisor and decided against the allow-list.

What happens next depends on the socket. A **stream** connection the supervisor makes itself,
handing the connected socket back, so the command never runs a stream `connect()` of its own.
Letting the kernel continue the original call would re-run it against whatever is in the
command's memory at that later moment, so a command could show one address to the check and
connect to another once it passed.

A **datagram** `connect()` and every datagram send that names a destination the supervisor makes
itself too. A `sendto()` with no address is the send of a connected socket, whose peer the
supervisor vetted when it made the connect, and the filter lets it through. It creates
each datagram socket of the command, keeps its own descriptor for the same open file
description, copies the address, the data and the lengths out of the command once, checks the
copies and sends from them. The call is never let through to the kernel, because the kernel would
read the address from the command's memory a second time, and a second thread could rewrite it in
between. Measured in an ordinary container, about one send in six reached an address the
allow-list never named before the guard did this, and none does now. The cost is spelled out in
[what Phobos does not protect against](/user/phobos/what-does-phobos-not-protect-against).

The guard judges the source port itself, because it runs outside Landlock. A connect or send on
a datagram socket that was never bound is refused unless the policy grants an ephemeral UDP
bind, which the layer tells it when a `udp` `[connect]` rule or a `[bind]` row of port 0 for
`udp` exists.

The guard refuses a raw, packet or ICMP socket before the socket exists, and refuses
`io_uring`, which would otherwise reach `connect` unseen.

The guard never lets the kernel run a command's own `listen()`. The kernel gives a socket that
was never bound a port of its choosing when it listens, and Landlock has no check for that, so
the guard creates and holds every stream socket of the command, runs `listen()` itself, and
refuses a socket that is unbound unless a `[bind]` row names port 0. The guard only ever acts on
a socket it made, so swapping another socket under the descriptor cannot create a listener. A
repeated `listen()` on a socket that already listens is answered with success and changes
nothing, including its backlog.

The guard enforces a rule by the address and the port it can see:

| The rule names | The guard holds it to |
| --- | --- |
| an address literal | that exact address |
| the name `localhost` | the whole loopback range, every `127.x.x.x` address and `::1` |
| a range in Classless Inter-Domain Routing (CIDR) notation | that network |
| a host name in a stream rule it cannot tie to an address | its port alone, with the host left to the broker |
| a host name in a `udp` rule | the addresses the name had when the run began |

A `connect` of a family the guard does not carry, a UNIX-domain socket among them, is refused
rather than made outside the Landlock view the command is held to.

:::warning[The guard is refused when missing, never skipped]
Where the connect guard program is missing or not executable, the layer ends the run with
`PHB-ERUNTIME`. A run cannot lose connect supervision unnoticed.
:::

## The egress broker

The guard reads a destination address, and it cannot read a Transport Layer Security (TLS)
ClientHello. A rule that names a host therefore constrains nothing about the onward address on
its own. The layer starts the egress broker automatically whenever the allow-list names a host,
rather than leaving that to a flag a run could forget.

The broker is an HAProxy on loopback. The guard hands it every allowed connection with a PROXY
protocol header naming the destination the command meant, and the broker decides the host:

- For an **exact name** it does not trust the header at all. It resolves the name itself,
  through the resolver you gave, and connects only to that address.
- For an **address**, a range or `*`, the header's destination is used unchanged.

The broker decides a connection to a port no name rule names at once. On a port a name rule
names, it reads the TLS host name first. A server there that speaks first, as SMTP, MySQL or SSH
do, therefore reaches its client only after the broker's five-second inspection delay.

A name with a star in it, such as `*.example.org`, never reaches the broker. The layer refuses
it with `PHB-EPOLICY` before it starts anything, because a wildcard cannot resolve to an
address.

An exact name needs a resolver, and the layer refuses the run with `PHB-ERUNTIME` where none
was given rather than running without the host-name enforcement the rule asked for. Each exact
name is mapped to a loopback placeholder in `/etc/hosts` beforehand, so the command's own name
resolution succeeds without a DNS query the guard would refuse.

Starting the broker changes the run's posture, and the layer says so on standard error: the
broker's onward connection needs a real network, so a rule that names a host cannot work in a
container started with `--network none`.

## A host name in a `udp` rule

A datagram carries no TLS host name for the broker to read, so a `udp` rule that names a host is
held to the addresses the name had at the start of the run. Before the command starts, the layer
runs the guard in its resolve mode, which asks the resolver you gave for the A and AAAA records of
each name and nothing else. It never reads `/etc/resolv.conf`. The guard is then given one rule
for each address, at most sixteen for a name (the IPv4 records first, the rest dropped without
refusing the run), and the command is shown the same addresses in
`/etc/hosts`, so the two cannot disagree about where the name leads. The `/etc/hosts` lines hold
the real addresses, not the loopback placeholder a stream name gets.

The answer is a snapshot. An address the name gains later is not reachable, and one it loses
stays reachable until the run ends. The lookup reads an answer that whoever controls the name's
domain influences, so it takes an address only from a record that belongs to the name asked or to
a chain of aliases that leads from it, and refuses a truncated or malformed answer.

The layer refuses the run with `PHB-ERUNTIME`, before the command starts, where no resolver was
given, a name does not resolve, `/etc/hosts` already maps the name to a different set of
addresses, more than 64 names need resolving, or the addresses add up to more rules than the
guard keeps, 256. A name written in two
cases is resolved once. The lookup needs a networked container, as a stream name does.

## The inbound filter

An `[accept]` rule starts a second HAProxy that binds the public port, rejects a connection
whose source address is not in the rule's list, and forwards an admitted one to the backend
port on loopback. A public port with no source admits nobody, which is the fail-closed
direction.

This assumes a networked container, so the layer says so loudly before it starts. Where the
filter cannot start, the run is refused rather than left with the listener exposed. With the
network restriction disabled, `phobos.sh` reports that the `[accept]` rule starts no filter and
that the listener's port is not locked either.

## The Landlock port rules

`[connect]` and `[bind]` produce `--connect-tcp`, `--bind-tcp`, `--connect-udp` and
`--bind-udp`. The two `udp` flags need a Landlock version 10 kernel, and below it the enforcer
refuses the run with exit status 125. The layer applies them on a Landlock ruleset of its
own, created with `--no-filesystem`, which composes with the filesystem layer's ruleset by
intersection. It is applied inside the guard's child lineage, after the supervisor has forked,
so the supervisor that connects on the command's behalf stays unrestricted.

The ruleset is applied on every run, including a run whose policy names no port, because it
carries `--close-bind`: both bind directions are handled with nothing granted, so only a `[bind]`
row opens a port. A row for port 0 becomes `--ephemeral-bind-tcp` or `--ephemeral-bind-udp`,
which grants a port the kernel chooses and never one the command names. On a kernel below
Landlock version 4 (TCP) or 10 (UDP) the direction cannot be closed: the layer's enforcer says
so on every run and leaves it open, and `--minimum-landlock-version` in the tail flags makes that
a refusal. A missing Landlock program ends the run with `PHB-ERUNTIME`.

Two details are worth knowing before a policy surprises you:

- **A rule that names no port cannot be expressed.** Only a host that is exactly one loopback
  address can omit its port: `localhost`, one address in `127.0.0.0/8`, or `::1`, each optionally
  with `/32` or `/128`. A section that holds one leaves that transport's port layer off, and the
  layer says so; the guard still filters the run. Phobos refuses a range such as `127.0.0.1/1`, a
  name such as `127.evil.example` and an external host with no port with `PHB-EPOLICY`.
- **A concrete port beside such a rule gets no Landlock rule either.** Landlock cannot keep
  loopback open on every port and close the rest, so the guard alone enforces that port, by
  host and port, and the layer logs the ports this applies to. For udp the rule
  needs no Landlock version 10 either.

A `udp` `[connect]` rule brings `--ephemeral-bind-udp` with it, for the source port the kernel
auto-binds to an outgoing datagram. Without it, an allowed send would be denied its own source
port, now that UDP bind is always handled.

## Further reading

- [Network subsystem](/contributor/subsystems/network): the same layer from the inside
- [Seccomp](/contributor/technologies/seccomp): how the guard traps a call
- [HAProxy](/contributor/technologies/haproxy): the two roles it plays here
- [`[connect]`](/user/policy-reference/connect) and [`[bind]`](/user/policy-reference/bind):
  the rule syntax in full
