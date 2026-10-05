---
title: "Allowing exactly one host"
sidebar_position: 4
description: "Permitting an outbound connection to one host and port, and the three ways of naming it."
---

:::tip[Simple Story]
The telephone reaches one number.

Whether that is a number, an exchange or a name in a directory changes who checks it, and the
name is the one that needs somebody able to read the directory.
:::

## The situation

The command fetches something over the network: a dependency, a data set, a licence check. One
destination is legitimate, and nothing else is.

## The policy fragment

The simplest version names an address and a port:

```ini title="exercise.cfg"
[connect]
allow 192.0.2.10:443
```

The connect guard holds that rule to that exact address. Landlock enforces the port in the
kernel besides, unless the policy carries a loopback rule with no port: see the warning under
Notes.

Where the service rotates its addresses, name the range:

```ini title="exercise.cfg"
[connect]
allow 198.51.100.0/24:443
```

Where only the name is stable, name the host and give the run a resolver:

```ini title="exercise.cfg"
[connect]
allow repo.example.org:443
```

```bash
${PHOBOS_HOME}/phobos.sh --config exercise.cfg --resolver 192.0.2.53 -- <your command>
```

The network layer starts the egress broker for a name rule, and the broker resolves the name
itself and connects only to that address. Without `--resolver` the run is refused with
`PHB-ERUNTIME` rather than run with the host unenforced.

## What this still forbids

- every other host on port 443
- the same host on every other port
- a raw, packet or ICMP socket, refused by the connect guard before it exists
- a UNIX-domain `connect`, refused rather than made outside the Landlock view
- `io_uring`, which would otherwise reach `connect` unseen

## The tempting wrong version

```ini title="wrong.cfg"
[connect]
allow repo.example.org
```

An external host with no port cannot be enforced, because Landlock enforces ports rather than
hosts. The run is refused with `PHB-EPOLICY` rather than started with a rule nothing holds.
Only a loopback host may omit its port.

The second tempting version passes and grants far more than it reads as:

```ini title="also-wrong.cfg"
[connect]
allow *:443
```

`*` names every host. It is occasionally what you want; it is rarely what the sentence "allow
the repository" meant.

## Notes

:::warning[The shipped base policies carry a loopback wildcard]
`BaseLanguage-java.cfg` and `BaseLanguage-python.cfg` each name three loopback rules with no
port:

```ini
[connect]
allow 127.0.0.1:*
allow [::1]
allow localhost
```

A stream rule with a concrete port, added on top of one of those, starts the run. Landlock
cannot keep loopback open on every port and close the rest, so it gets no kernel rule, and the
connect guard alone holds the port, by host and port. The network layer says so on standard
error and names the port:

```text
network: the tcp ports 443 named beside it get no Landlock rule either, since Landlock cannot keep loopback open on every port and close the rest, so the connect guard alone enforces them, by host and port
```

The two transports are separate, and a [`[bind]`](/user/policy-reference/bind) rule is not
affected.
:::

- A name rule assumes a networked container, so it cannot work under `--network none`. The
  layer says so on standard error before it starts the broker.
- Phobos refuses a wildcard-label rule, `allow *.example.org:443`, with `PHB-EPOLICY`. A
  wildcard cannot resolve to an address, so the broker could only compare it with the name the
  sandboxed command presents. Name each host exactly.
- A datagram rule, `allow 203.0.113.53:53 udp`, needs Landlock version 10, except beside a udp
  loopback rule with no port, where the guard alone holds it. It can name a host,
  `allow dns.example.org:53 udp`, which is resolved once before the command starts through
  `--resolver` and held to the addresses it had then.
- Phobos accepts a loopback rule with no port beside a rule with a concrete port. Landlock cannot
  keep loopback open on every port and close the rest, so the connect guard alone enforces the
  port, and the run's log names it.
