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

The connect guard holds that rule to that exact address, and Landlock enforces the port in the
kernel besides.

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

A stream rule with a concrete port, added on top of one of those, ends the run before the
command starts:

```text
Policy unenforceable: '127.0.0.1:*' names no port, so Landlock cannot express it, while other
rules do name one. A half-enforced network policy would look stricter than it is. (PHB-EPOLICY)
```

A task configuration can only widen, so it cannot take the wildcard away. Reaching an external
host over a stream therefore needs the base policy for that runtime environment to name its
loopback ports concretely, which is a change to the shipped policy rather than to your
configuration.

Two rules are unaffected. A datagram rule does not collide, because the two transports are
collected apart, and neither does a [`[bind]`](/user/policy-reference/bind) rule.
:::

- A name rule assumes a networked container, so it cannot work under `--network none`. The
  layer says so on standard error before it starts the broker.
- A wildcard-label rule, `allow *.example.org:443`, matches the Transport Layer Security host
  name by suffix and forwards to the destination the header carried. It does not itself
  constrain the onward address, so it is the weaker of the two name forms.
- A datagram rule, `allow 203.0.113.53:53 udp`, needs Landlock version 10 and may not name a
  host name, since host enforcement rests on the Transport Layer Security host name.
- Mixing a loopback rule with no port and a rule with a concrete port in one section is
  refused: one would be kernel-enforced and the other would not.
