---
title: "HAProxy"
sidebar_position: 3
description: "The two roles HAProxy plays: the egress broker that enforces a host name, and the inbound filter that admits a source."
---

:::tip[Simple Story]
Two people sit outside the room. One places every outgoing call and checks who answers; the
other stands at the door and turns away visitors who are not on the list.

They are the same person hired twice, for two different jobs.
:::

## What it is

HAProxy is a proxy for streams. Phobos runs it in transparent mode, so it forwards bytes rather
than parsing an application protocol, and it uses two of its features: inspecting the start of
a connection before deciding, and resolving a name through a nominated resolver.

Both instances are **trusted infrastructure**, started before the command and outside the
sandbox. Both run in the foreground with `-db`, so they stay children of the layer that started
them and inside the run's process group, and both write their own output to a scratch log
rather than to the command's streams. The layer records each process identifier in the
specification directory, because it replaces itself with the rest of the chain and cannot stop
them itself; whichever layer ends the run stops them.

## Role one: the egress broker

The connect guard decides by address and port. It cannot see a Transport Layer Security (TLS)
ClientHello, so a rule that names a host constrains nothing about the onward address on its
own. The broker is what makes such a rule mean something.

The guard hands every allowed connection to the broker on loopback, with a PROXY protocol
version 2 header naming the destination the command meant. The broker then decides the host:

| The rule names | What the broker does |
| --- | --- |
| an exact name | resolves the name itself, through the `phobosdns` resolver, sets the destination to that address, and rejects the connection where the name does not resolve |
| a name suffix, `*.example.org` | matches the Server Name Indication (SNI) host name by suffix and forwards to the header's destination |
| an address or a range | accepts as soon as the destination matches, so a connection with no ClientHello does not wait out the inspection delay |
| `*` | accepts everything and forwards to the header's destination |

The exact-name case is the strong one, and it is the reason the network layer refuses such a
rule without `--resolver`: the broker does not trust the header at all there, so a command that
presents an allowed name while aiming at another address is still sent only to where the name
resolves. The suffix case is weaker by construction, since a suffix cannot be resolved to one
address.

Each exact name is mapped to a loopback placeholder in `/etc/hosts` first, so the command's own
name resolution succeeds without a query the guard would refuse. The broker does not consult
that file: it asks the resolver.

The port was already enforced by the guard before the redirect, so the broker decides the host
alone.

## Role two: the inbound filter

An `[accept]` rule produces a second instance with one frontend per public port:

```
frontend in_18080
    bind :::18080 v4v6
    tcp-request connection reject if !{ src -f <sources for 18080> }
    default_backend be_18080

backend be_18080
    server s 127.0.0.1:8080
```

The source list is a file per port, written beside the configuration. A public port with no
source gets an empty file, so the frontend rejects every peer: the fail-closed direction.

The filter binds the public port itself, which is why a public port the command may bind too
is refused by the policy check. It forwards to the backend port on loopback, which is why
a backend port `[bind]` does not name is refused as well.

## What neither role is

The broker is not a boundary on its own. It rests on the connect guard having vetted the port
and redirected the connection; a command that could reach the network without going through the
guard would not meet the broker at all.

The inbound filter is defence in depth. It sees only the connections that arrive at it, and
that the backend is reachable *only* through it comes from the container's network isolation
rather than from HAProxy.

## Further reading

- [HAProxy documentation](https://docs.haproxy.org/) — the configuration manual
- [The PROXY protocol](https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt) — the header
  the guard sends
- [`haproxy/haproxy`](https://github.com/haproxy/haproxy) — the source repository
- [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) — Server Name Indication, the field the
  broker reads
