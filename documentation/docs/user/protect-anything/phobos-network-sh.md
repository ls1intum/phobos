---
title: "phobos-network.sh"
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
${PHOBOS_HOME}/phobos-network.sh --config exercise.cfg -- curl https://example.org
```

| Option | What it is for |
| --- | --- |
| `--config <file>` | A configuration to build the specification from. Repeatable. |
| `--spec-parent <dir>` | Where the specification directory is made. The default is `/var/tmp`. |
| `--tail-flags-file <file>` | The tail flags file to apply. |
| `--connect-guard-bin <path>` | The connect guard program to use. |
| `--haproxy-bin <path>` | The HAProxy program the broker and the inbound filter run as. |
| `--resolver <ip[:port]>` | The Domain Name System (DNS) resolver the broker resolves an exact host name through. |
| `--landlock-bin <path>` | The `phobos-landlock` program that applies the port rules. |
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

A **datagram** `connect()` only sets a default peer, which cannot be swapped that way, so it is
checked and then let through to the kernel. The boundary for a datagram is the checked send
that follows and the container's own isolation, rather than a connection the supervisor made.

The guard refuses a raw, packet or ICMP socket before the socket exists, and refuses
`io_uring`, which would otherwise reach `connect` unseen. An ordinary datagram socket it
creates and tracks, so that a send through it is judged later.

The guard enforces a rule by the address and the port it can see:

| The rule names | The guard holds it to |
| --- | --- |
| an address literal, or the name `localhost` | that exact address |
| a range in Classless Inter-Domain Routing (CIDR) notation | that network |
| a host name it cannot tie to an address | its port alone, with the host left to the broker |

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
- For a **name suffix**, `*.example.org`, it matches the Server Name Indication (SNI) host name
  by suffix and forwards to the header's destination.
- For an **address**, a range or `*`, the header's destination is used unchanged.

An exact name needs a resolver, and the layer refuses the run with `PHB-ERUNTIME` where none
was given rather than running without the host-name enforcement the rule asked for. Each exact
name is mapped to a loopback placeholder in `/etc/hosts` beforehand, so the command's own name
resolution succeeds without a DNS query the guard would refuse.

Starting the broker changes the run's posture, and the layer says so on standard error: the
broker's onward connection needs a real network, so a rule that names a host cannot work in a
container started with `--network none`.

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

`[connect]` and `[bind]` produce `--connect-tcp`, `--bind-tcp` and, on a Landlock version 10
kernel, `--connect-udp` and `--bind-udp`. The layer applies them on a Landlock ruleset of its
own, created with `--no-filesystem`, which composes with the filesystem layer's ruleset by
intersection. It is applied inside the guard's child lineage, after the supervisor has forked,
so the supervisor that connects on the command's behalf stays unrestricted.

Two details are worth knowing before a policy surprises you:

- **A rule that names no port cannot be expressed.** Only a loopback host may omit its port. A
  section made only of those leaves that transport's port layer off, and the layer says so; the
  guard still filters the run. An external host with no port is refused with `PHB-EPOLICY`.
- **A wildcard beside a concrete port is refused.** Mixing them would make one rule
  kernel-enforced and the other not, which reads stricter than it is.

Where the policy handles both datagram directions, Phobos adds `--bind-udp 0` for the ephemeral
source port the kernel auto-binds to an outgoing datagram. Without it, an allowed send would be
denied its own source port.

## Further reading

- [Network subsystem](/contributor/subsystems/network) — the same layer from the inside
- [Seccomp](/contributor/technologies/seccomp) — how the guard traps a call
- [HAProxy](/contributor/technologies/haproxy) — the two roles it plays here
- [`[connect]`](/user/policy-reference/connect) and [`[bind]`](/user/policy-reference/bind) —
  the rule syntax in full
