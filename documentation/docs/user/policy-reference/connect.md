---
title: "[connect]"
sidebar_position: 9
description: "The outbound destinations a command may reach, by host, port and transport."
---

:::tip[Simple Story]
The telephone reaches the numbers on the list.

Somebody outside the room dials each one, checks it against the list first, and hands back the
line. The handset itself cannot dial at all.
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

# policy-focus-start
[connect]
allow 192.0.2.10:443
allow repo.example.org:443
allow 203.0.113.53:53 udp
# policy-focus-end

[bind]
allow 8080
allow 5353 udp

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
allow <host>[:<port>] [udp|tcp]
```

The transport marker is optional and defaults to `tcp`, so a rule written before datagrams
existed keeps its meaning.

| The host may be | Example | How it is held |
| --- | --- | --- |
| an address literal | `allow 192.0.2.10:443` | to that exact address, by the connect guard |
| a loopback name or address | `allow localhost`, `allow [::1]` | to loopback, by the connect guard |
| a range in Classless Inter-Domain Routing (CIDR) notation | `allow 198.51.100.0/24:443` | to that network, by the connect guard |
| an exact host name | `allow repo.example.org:443` | to the address that name resolves to, by the egress broker |
| a name with a leading wildcard label | `allow *.example.org:443` | by suffix on the Transport Layer Security (TLS) host name, by the egress broker |
| `*` | `allow *:443` | every host on that port |

An address in the sixth version of the Internet Protocol carries colons of its own, so a port
is written in brackets: `allow [2001:db8::1]:443`. A bare `allow 2001:db8::1` is the host with
no port.

## Which ports may be left out

A loopback host may omit its port, and no other host may. Landlock enforces ports rather than
hosts, so an external host with no port cannot be expressed at all, and the run is refused with
`PHB-EPOLICY` rather than started with a rule nothing enforces. Mixing a loopback wildcard with
a concrete port in the same section is refused for the same reason: one rule would be
kernel-enforced and the other would not.

A port is a whole number from 1 to 65535. `host:0` names no port that exists and is a policy
mistake, never a licence to switch the port layer off.

## What enforces it

One allow-list becomes three expressions of the same rules:

| Enforcer | What it decides | Where it runs |
| --- | --- | --- |
| the connect guard | host address and port | outside the process, at the seccomp boundary |
| Landlock port rules | the port alone, per transport | in the kernel, through `--connect-tcp` and `--connect-udp` |
| the egress broker | the host name | in an HAProxy the network layer starts for a name rule |

seccomp stops a `connect` before the kernel path where Landlock would check the port, and the
supervisor then connects outside Landlock. Where the guard runs it is therefore the whole
connect boundary, host and port, and the Landlock ports remain a second, kernel-enforced
expression of the same ports.

## The datagram marker

A `udp` rule is handed to Landlock as `--connect-udp`, which is the `CONNECT_SEND_UDP` right
and covers both connecting a datagram socket and sending a datagram. The connect guard enforces
it for the datagram transport apart from the stream one, so a `udp` rule never admits a stream
connection to the same host and port, nor the reverse.

Two limits come with it:

- **It needs Landlock version 10.** On an older kernel `phobos-landlock` refuses the run with
  `[phobos-landlock] UDP network rules require Landlock version 10` and exit status 125, rather
  than running with the transport left unenforced.
- **It may not name a host name.** Host enforcement rests on the TLS host name, which is a
  stream concept, so a `udp` rule names an address, a range, a loopback name or `*`.

## Notes

**An exact name needs a resolver.** The broker binds the name to its own address by resolving
it, and the network layer refuses the run with `PHB-ERUNTIME` where `--resolver` was not given.

**A name rule assumes a networked container.** The broker has to make the onward connection, so
a run with `--network none` cannot serve such a rule. The network layer says so on standard
error before it starts the broker.

**A suffix rule is the weaker match.** It routes by the TLS host name to the destination the
header carried and does not itself constrain the onward address.

**A concrete stream port collides with the shipped base policies.** Both of them name three
loopback rules with no port, and a section may not mix a wildcard with a concrete port on one
transport. A task configuration can only widen, so adding `allow 192.0.2.10:443` on top of one
of them ends the run with `PHB-EPOLICY`; the base policy has to name its loopback ports
concretely first. A datagram rule is judged apart and does not collide.

**There is no separate toggle for opening, sending and receiving.** A rule names a host, a port
and a transport, or it does not.

## Further reading

- [Allowing exactly one host](/user/policy-cookbook/allowing-exactly-one-host) — the recipe
- [phobos-network.sh](/user/protect-anything/phobos-network-sh) — the layer that applies it
- [HAProxy](/contributor/technologies/haproxy) — how the broker decides
