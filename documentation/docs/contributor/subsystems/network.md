---
title: "Network"
sidebar_position: 3
description: "The connect guard, the two HAProxy roles and the Landlock port rules, and how they compose."
---

:::tip[Simple Story]
One allow-list, written down once and enforced in three places.

Each of the three sees something the others cannot, which is why none of them is redundant.
:::

## What it does

`phobos-network.sh` owns the whole network restriction. `phobos.sh` includes the layer only
where the network restriction is enabled, so there is no enable flag to read inside it.

## What is in it

| File | Purpose |
| --- | --- |
| `phobos-network.sh` | the layer: the broker, the inbound filter, the port rules, the guard |
| `phobos-haproxy.sh` | classification, the two configurations, and starting each instance |
| `phobos-network-args.sh` | `[connect]` and `[bind]` to the Landlock port arguments |
| `phobos-connect-guard.c` | the sequence of stages: load, fork, supervise, wait |
| `phobos-connect-guard-child.c` | the filter and the handover of the notification descriptor |
| `phobos-connect-guard-supervisor.c` | the decision on every trapped call |
| `phobos-connect-guard-rules.c` | the allow-list and the decision on a destination |
| `phobos-connect-guard-destination.c` | a destination read out of the command's memory |
| `phobos-connect-guard-socket-types.c` | the type of every socket, remembered by inode |
| `phobos-connect-guard-options.c` | the command line |
| `phobos-connect-guard-diagnostics.c` | the setup exit status and the verbose lines |

## The three enforcers

| Enforcer | Sees | Decides | Cannot see |
| --- | --- | --- | --- |
| the connect guard | the destination address of a call | host address and port | the Transport Layer Security host name |
| Landlock port rules | the port, per transport | the port | the host |
| the egress broker | the ClientHello | the host name | anything the guard did not send it |

The guard is the whole connect boundary where it runs, because seccomp stops a call before the
kernel path where Landlock would check the port, so the supervisor connects outside Landlock.
The port rules remain the kernel-enforced second expression of the same ports, which is what
holds a raw system call that never reaches the guard's filter.

## Why the broker is started automatically

A rule that names a host constrains nothing about the onward address unless somebody reads the
host name. Making that a flag would let a run forget it and silently widen the rule to any
address on the port, so `name_connect_rules` reads the allow-list and the layer starts the
broker wherever it finds an exact name or a suffix.

`classify_connect_host` is the one classifier the configuration generator and the layer share,
so the two can never disagree about what an exact name is. It treats `localhost` as an address
rather than a name: the guard already resolves it to the loopback the command connected to.

The order of the refusals matters and is pinned: a missing guard and an exact name without a
resolver both end the run **before** the notice that a broker is starting, so a run that never
started one does not log that it did.

## Where each Landlock ruleset is applied

The layer applies the port rules on a ruleset of its own, created with `--no-filesystem`. Two
properties follow:

- It composes with the filesystem layer's ruleset by intersection, so neither widens the other,
  and `--no-filesystem-restriction` leaves the port rules untouched.
- It is applied **inside the guard's child lineage**, after the supervisor has forked, so the
  supervisor that connects on the command's behalf is never restricted by it.

`add_udp_ephemeral_bind_if_needed` adds `--bind-udp 0` where the policy handles both datagram
directions, because the kernel auto-binds an ephemeral source port for an outgoing datagram and
gates that auto-bind by `BIND_UDP` once the right is handled. The rule is added in that one
case alone, so a stream-only policy gains nothing.

## The guard, stage by stage

```
load_rules            -> refuses to run rather than fall open where the file cannot be read
configure_broker      -> where the layer gave it one
socketpair + fork
  child:  run_child   -> install the filter, send the descriptor up, exec the rest of the chain
  parent: ignore SIGTERM, receive the descriptor, supervise, wait, exit with the child's status
```

`SIGTERM` is ignored only **after** the fork. The command keeps the default disposition, so an
outer timeout's escalation reaches it rather than the supervisor.

Where the descriptor never arrives, the parent waits for the child, reports that the command
could not be supervised, and ends with the child's status, or with the setup status where the
child succeeded.

## Known gaps

**Datagram egress is filtered by port and by the checked send, never by host name.** Host
enforcement rests on the Transport Layer Security host name, which is a stream concept, so a
datagram rule may not name a host. Datagram traffic beyond the allow-list is the container's
boundary.

**The broker picks a loopback port at random and probes it.** It tries five candidates between
20000 and 60000 and skips one that already answers. A probe that answers on a live broker is
answering the broker, because the broker holds the port exclusively, but the window itself is a
retry loop rather than a reservation.

**The placeholder entry in `/etc/hosts` is appended, never removed.** It is written before the
filesystem layer makes `/etc` read-only, under a marker line, and re-running skips a name that
is already mapped.

**`[accept]` is stream only.** There is no datagram inbound filter.

## Further reading

- [Seccomp](../technologies/seccomp.md) — how a call is trapped and answered
- [HAProxy](../technologies/haproxy.md) — the two roles in detail
- [phobos-network.sh](/user/protect-anything/phobos-network-sh) — the same layer, from the
  outside
- [`[connect]`](/user/policy-reference/connect), [`[bind]`](/user/policy-reference/bind),
  [`[accept]`](/user/policy-reference/accept)
