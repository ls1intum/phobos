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

`phobos-networksystem.sh` owns the whole network restriction. `phobos.sh` includes the layer only
where the network restriction is enabled, so there is no enable flag to read inside it.

## What is in it

| File | Purpose |
| --- | --- |
| `phobos-networksystem.sh` | the layer: the broker, the inbound filter, the port rules, the guard, and the clean-up after the run |
| `phobos-tools-networksystem/phobos-haproxy.sh` | classification, the two configurations, starting each instance, the `udp` name expansion and the `/etc/hosts` writers |
| `phobos-tools-networksystem/phobos-network-args.sh` | `[connect]` and `[bind]` to the Landlock port arguments, and the refusals |
| `phobos-seccomp-networksystem/phobos-seccomp-networksystem.c` | the sequence of stages: load, fork, supervise, wait |
| `phobos-seccomp-networksystem/phobos-seccomp-networksystem-child.c` | the filter and the handover of the notification descriptor |
| `phobos-seccomp-networksystem/phobos-seccomp-networksystem-supervisor.c` | the decision on every trapped call, including `listen` |
| `phobos-seccomp-networksystem/phobos-seccomp-networksystem-datagram.c` | every datagram `connect` and send, made by the supervisor from copies |
| `phobos-seccomp-networksystem/phobos-seccomp-networksystem-resolve.c` | the resolve mode: the addresses of the host names a `udp` rule holds, looked up once |
| `phobos-seccomp-networksystem/phobos-seccomp-networksystem-rules.c` | the allow-list and the decision on a destination |
| `phobos-seccomp-networksystem/phobos-seccomp-networksystem-destination.c` | a destination read out of the command's memory |
| `phobos-seccomp-networksystem/phobos-seccomp-networksystem-socket-types.c` | the type of every socket, remembered by inode |
| `phobos-seccomp-networksystem/phobos-seccomp-networksystem-held-sockets.c` | the sockets the supervisor created and still holds, least recently used first out, and the ones it let listen |
| `phobos-seccomp-networksystem/phobos-seccomp-networksystem-options.c` | the command line |
| `phobos-seccomp-networksystem/phobos-seccomp-networksystem-diagnostics.c` | the setup exit status and the verbose lines |

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
broker wherever it finds an exact name. A wildcard name is not one. The layer first runs
`refuse_wildcard_connect_names` over every row of its rules, in its own shell, so it judges a
hand-written specification too.

`classify_connect_host` is the one classifier the configuration generator and the layer share,
so the two can never disagree about what an exact name is. It treats `localhost` as an address
rather than a name: the guard already resolves it to the loopback the command connected to. It
answers `invalid` for a host with a star in it other than `*`. It tests that before the address
shortcuts, so a star beside a slash or a colon never counts as an address.

The order of the refusals matters and is pinned: a missing guard and an exact name without a
resolver both end the run **before** the notice that a broker is starting, so a run that never
started one does not log that it did.

## A host name in a `udp` rule

A datagram has no TLS host name for the broker to read, so `name_connect_rules` and
`exact_connect_names` skip `udp` rows and a `udp` name never starts the broker. The layer
handles it before anything else:

1. `udp_connect_names` lists the exact names of the `udp` rows, in lower case and once each, so a
   name written in two cases is one name with one set of addresses.
2. The layer runs the guard as `phobos-seccomp-networksystem --resolve --resolver ADDRESS -- NAME...`.
   It prints `NAME ADDRESS` lines, or nothing and the setup status when any name fails. It needs
   `--resolver` and refuses without one.
3. `expand_udp_name_rules` writes `net.guard.rules`: every row of `net.rules`, except that a `udp`
   name row becomes one row per address on its own port. A name with no resolved line yields no
   row, which denies, so a name can never be read by the guard as matching its port alone. The
   file is listed in `PHB_SPEC_FILES`, so removing the specification directory removes it.
4. The layer refuses the run when that file passes the guard's 256 rules, a limit the guard
   applies by dropping rows quietly; `PHB_GUARD_RULES_MAXIMUM` is compared with the C constant by
   a test.
5. `write_resolved_hosts` maps each name to its real addresses in `/etc/hosts`, under the run's
   tag. `hosts_accepts` refuses it, before anything is written, unless the file holds none of the
   name yet or exactly these addresses, whoever's lines they are, with IPv6 compared in its full
   form. A check that cannot be made is a refusal too. The stream placeholder writer asks the same
   question, and a name a `udp` rule holds gets no placeholder.

The resolve mode itself builds the query by hand, with one question and an EDNS0 record, asks A
and then AAAA with two tries, each waiting up to one second, and ignores a packet whose id or
question is not the query's, at most four of them per try before the try counts as unanswered. It reads the answer with `read_name`, which follows compression pointers at most
sixteen times, accepts only letters, digits, hyphen and underscore in a label so that no label can
pass for two or for a shorter name, and lower-cases what it reads. It does not use the C library's
resolver or parser, because the static build does not carry them.

## The datagram path

The supervisor creates every INET datagram socket through the trapped `socket()` and keeps its
descriptor in the held-socket table beside the listen-capable sockets. `service_datagram_connect`
and `service_datagram_send` in `phobos-seccomp-networksystem-datagram.c` do the rest: they find
the held socket by the inode behind the command's descriptor, copy what the call names out of the
command, judge the destination against the `udp` rules and the source port against the
policy's ephemeral grant, and make the call on their own descriptor, answering with its result and
never continuing. The send waits for room on a blocking socket for one second at most per message, and a
notification that turns invalid while it reads is dropped without sending.

## Where each Landlock ruleset is applied

The layer applies the port rules on a ruleset of its own, created with `--no-filesystem`. Two
properties follow:

- It composes with the filesystem layer's ruleset by intersection, so neither widens the other,
  and `--no-filesystem-restriction` leaves the port rules untouched.
- It is applied **inside the guard's child lineage**, after the supervisor has forked, so the
  supervisor that connects on the command's behalf is never restricted by it.

- Bind is closed by default. The layer always passes `--close-bind`, so a command with no
  `[bind]` row cannot bind or listen on any port. A row for port 0 becomes
  `--ephemeral-bind-tcp` or `--ephemeral-bind-udp`, which grants only a port the kernel chooses.
  On a kernel that cannot close bind the program warns and carries on, because refusing there
  would stop every run.
- `add_udp_ephemeral_bind_if_needed` adds the ephemeral UDP grant where the policy handles
  datagrams, because the kernel auto-binds an ephemeral source port for an outgoing datagram and
  gates that auto-bind by `BIND_UDP` once the right is handled. A stream-only policy gains
  nothing from it.

## The listen guard

Landlock closes `bind`, but a socket that was never bound can still be made to listen, and the
kernel then picks a port nothing judged. The guard therefore traps `listen` as well. A stream
socket the command creates is made by the supervisor and handed over, and the supervisor keeps
its own descriptor for the same open file description in the held-socket table, keyed by inode.
When the command calls `listen`, the supervisor runs it on that descriptor, and only where the
socket is bound to a port `[bind]` named or is unbound and the policy allowed an ephemeral port.
A socket the supervisor does not hold, such as an inherited or accepted descriptor, or one
evicted from the full table, cannot listen. That fails closed.

## The guard, stage by stage

```
load_rules            -> refuses to run rather than fall open where the file cannot be read
configure_broker      -> where the layer gave it one
socketpair + fork
  child:  run_child   -> install the filter, send the descriptor up, exec the rest of the chain
  parent: ignore SIGTERM, receive the descriptor, supervise, wait, exit with the child's status
```

The network layer runs this guard as a child rather than replacing itself with it, so its `EXIT`
trap is still there when the command ends. That trap stops the broker and the inbound filter and
removes the run's own lines from `/etc/hosts`, after a normal exit, a refusal and a timeout alike.
The command's status is passed through unchanged.

`SIGTERM` is ignored only **after** the fork. The command keeps the default disposition, so an
outer timeout's escalation reaches it rather than the supervisor.

Where the descriptor never arrives, the parent waits for the child, reports that the command
could not be supervised, and ends with the child's status, or with the setup status where the
child succeeded.

## Known gaps

**A held datagram socket outlives the command's close.** The supervisor keeps its own descriptor
for every datagram socket until the table of 512 held sockets, shared with the listen-capable
ones, is full and the socket is the least recently used, so a port the socket was bound to stays
taken and datagrams queued for it stay in memory. A socket the table has evicted can no longer
send to a destination, which fails closed. Releasing an entry when no process of the run holds its
inode any more would need a scan of `/proc`, and is not done.

**`sendmsg` and `sendmmsg` are refused unless the socket is a held datagram socket.** A TCP or
UNIX socket the supervisor holds for `listen` does not count, nor does one it does not hold, because the address sits in memory a second thread could rewrite after a
datagram socket was swapped under the descriptor.

**A name in a `udp` rule is a snapshot.** The layer resolves it once, so an address the name gains
later is not reachable and one it loses stays reachable until the run ends. The lookup reads an
answer that the name's owner influences, so the resolve mode takes an address only from a record
that belongs to the name asked or to an alias chain from it, follows at most eight aliases, and
refuses a truncated or malformed answer rather than use part of it. It speaks UDP only, with an
EDNS0 size of 1232, so an answer that does not fit refuses the run.

**The broker picks a loopback port at random and probes it.** It tries five candidates between
20000 and 60000 and skips one that already answers. A probe that answers on a live broker is
answering the broker, because the broker holds the port exclusively, but the window itself is a
retry loop rather than a reservation.

**The placeholder entry in `/etc/hosts` is removed only by the layer that wrote it.** It is
written before the filesystem layer makes `/etc` read-only, under a marker line tagged with the
run, and the layer's `EXIT` trap removes exactly those lines. A run that is killed with
`SIGKILL` skips the trap and leaves them behind, and re-running skips a name that is already
mapped.

**`[accept]` is stream only.** There is no datagram inbound filter.

## Further reading

- [Seccomp](../technologies/seccomp.md) — how a call is trapped and answered
- [HAProxy](../technologies/haproxy.md) — the two roles in detail
- [phobos-networksystem.sh](/user/protect-anything/phobos-network-sh) — the same layer, from the
  outside
- [`[connect]`](/user/policy-reference/connect), [`[bind]`](/user/policy-reference/bind),
  [`[accept]`](/user/policy-reference/accept)
