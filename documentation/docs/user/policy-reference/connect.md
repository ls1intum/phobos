---
title: "[connect]"
sidebar_position: 10
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

# Devices that may receive ioctl calls, here the pseudo-terminals of the container.
[ioctl]
/dev/pts

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
| `*` | `allow *:443` | every host on that port |

Phobos refuses a host name with a star in it, such as `allow *.example.org:443`, with
`PHB-EPOLICY`, for either transport. The broker pins an exact name by resolving it itself. A
wildcard name cannot resolve to an address, so the broker could only compare the name the
sandboxed command presents and learn nothing about where the connection goes. Name each host
exactly. The bare `*` is the one star that stays.

An address in the sixth version of the Internet Protocol carries colons of its own, so a port
is written in brackets: `allow [2001:db8::1]:443`. A bare `allow 2001:db8::1` is the host with
no port.

## Which ports may be left out

Only a host that is exactly one loopback address can omit its port: `localhost`, one address in
`127.0.0.0/8`, `::1` in any spelling, or its IPv4-mapped form `::ffff:127.x.y.z`, each optionally
with `/32` or `/128`. Phobos refuses a range such as `127.0.0.1/1`, a name such as
`127.evil.example` and any other host with no port, and names the file and the line. Without a
port, nothing but the connect guard holds the host, and the guard holds a range to every address
in it, so a range opens far more than loopback. Landlock enforces ports rather than hosts, so it
cannot express an external host with no port. Phobos refuses that run with `PHB-EPOLICY` rather
than start it with a rule that nothing enforces. Phobos accepts a concrete port beside a loopback
wildcard in the same section. Landlock cannot keep loopback open on every
port and close the rest, so the layer stays off for that transport. The connect guard alone
enforces the port, by host and port, and the network layer logs the ports concerned.

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
connection to the same host and port, nor the reverse. Landlock cannot express a `udp` rule that
names a port beside a `udp` loopback rule with no port, so that rule gets no `--connect-udp`.
The guard alone holds it, and it needs no Landlock version 10.

Two limits come with it:

- **It needs Landlock version 10 wherever Phobos emits `--connect-udp`.** On an older kernel `phobos-landlock-filesystem-and-networksystem` refuses the run with
  `[phobos-landlock-filesystem-and-networksystem] UDP network rules require Landlock version 10` and exit status 125, rather
  than running with the transport left unenforced.
- **A host name in it is resolved once, at the start.** Host enforcement for a stream rests on the
  Transport Layer Security (TLS) host name, which a datagram does not carry. The network layer
  therefore looks the name up before the command starts, through `--resolver`, and holds the rule
  to the addresses it had then, at most sixteen. The command is shown the same addresses in
  `/etc/hosts`. An address the name gains later is not followed, and a name that does not resolve
  refuses the run. A name with a star in it is refused, as for a stream rule.

## Notes

**An exact name needs a resolver.** The broker binds the name to its own address by resolving
it, and a `udp` name is resolved once at the start, and the network layer refuses the run with
`PHB-ERUNTIME` where `--resolver` was not given.

**A name rule assumes a networked container.** The broker has to make the onward connection, so
a run with `--network none` cannot serve such a rule. The network layer says so on standard
error before it starts the broker.

**Phobos refuses a wildcard name.** `allow *.example.org:443` ends the run with `PHB-EPOLICY`
when Phobos reads the policy, and so does a hand-written `net.rules` that holds one. Write one
rule per host, or an address range for a service whose addresses rotate.

**A concrete stream port beside the shipped base policies has no kernel rule.** Both of them
name three loopback rules with no port. Phobos accepts `allow 192.0.2.10:443` on top of one of
them, and the connect guard alone enforces the port, by host and port, while the network layer
is on. The run's log names the port. A udp rule that names a port beside a udp loopback
wildcard needs no Landlock version 10 either.

**An IPv4-mapped destination is the IPv4 endpoint it maps.** A program that opens an IPv6 socket to reach an
IPv4 peer, as a Java virtual machine does by default, connects to `::ffff:192.0.2.10`. That is the
same endpoint as `192.0.2.10`, so the guard judges it as that address. A literal IPv4 rule,
`localhost` and an IPv4 range cover it exactly as they cover the IPv4 spelling, on the same ports
and the same transport, and no rule covers more through it. An IPv6 literal rule still covers
only the IPv6 address it names. Landlock enforces ports only, from the socket address's port
whatever its family, so its view stays the same.

**The guard names what it refuses under `--debug`.** Run verbosely, it prints each destination the
allow-list does not name by address and port, an IPv6 address in brackets, for example
`refusing connect to a destination the allow-list does not name: [2001:db8::1]:443`.

**There is no separate toggle for opening, sending and receiving.** A rule names a host, a port
and a transport, or it does not.

## Further reading

- [Allowing exactly one host](/user/policy-cookbook/allowing-exactly-one-host): the recipe
- [phobos-networksystem.sh](/user/protect-anything/phobos-network-sh): the layer that applies it
- [HAProxy](/contributor/technologies/haproxy): how the broker decides
