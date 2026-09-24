---
title: "[accept]"
sidebar_position: 11
description: "Fronting a local listener with an inbound filter that admits only the named source addresses."
---

:::tip[Simple Story]
Somebody sits at the door and turns away every visitor who is not on the list.

A doorkeeper is worth having. A doorkeeper is not a wall, and this page says which of the two
you are getting.
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

[connect]
allow 192.0.2.10:443
allow repo.example.org:443
allow 203.0.113.53:53 udp

[bind]
allow 8080
allow 5353 udp

# policy-focus-start
[accept]
expose 18080 to 8080 from 198.51.100.0/24
# policy-focus-end

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
expose <public-port> to <backend-port> from <source>[, <source>...]
```

```ini
[accept]
expose 18080 to 8080 from 198.51.100.0/24
```

| Part | What it is | Rules |
| --- | --- | --- |
| `<public-port>` | the port the container exposes | at or above 1024, and not a `[bind]` port |
| `<backend-port>` | the command's own listening port | must be named in [`[bind]`](bind.md) |
| `<source>` | an address or a range, separated by commas | either version of the Internet Protocol |

The literal words `expose`, `to` and `from` are all required, `from` included on a rule that
names no source.

Two rules may not front the same public port with different backends. A rule with no source
admits nobody, which is the fail-closed direction, and Phobos warns that the service is
unreachable.

## What enforces it

The network layer starts a second HAProxy, the inbound filter. For each public port it binds
that port on both address families, rejects a connection whose source is not in the port's
list, and forwards an admitted one to the backend port on loopback. Where the filter cannot
start, the run is refused rather than left with the listener exposed.

The three refusals in the table above are checked once the whole policy has been merged, since
only then is the full `[bind]` set known:

- a public port below 1024 cannot be bound without a capability the run does not have;
- a public port the command may itself bind would let it take the port before the filter and
  receive unfiltered connections;
- a backend port that `[bind]` does not name would leave the filter forwarding to a listener
  that never comes up.

## Notes

:::warning[This is defence in depth, not a boundary]
An `[accept]` rule changes the run's posture, and Phobos says so loudly on standard error.

- **It removes `--network none`.** An external client cannot reach a container with no network.
- **Phobos locks the port, not its reachability.** Landlock refuses the command a listener on
  any other port, in the kernel and against raw system calls. The bind right is per port rather
  than per address, so the command may bind the backend port on every interface. That the
  backend is reachable only through the filter comes from the container's network isolation: a
  dedicated network with inter-container communication disabled, only the public port
  published, nothing else exposed.
- **A source address is weak authentication.** It resists spoofing only for an established
  handshake, and network address translation makes it coarse.
:::

**Stream connections only.** There is no datagram equivalent of this section.

**With the network restriction disabled, the rule does nothing.** `phobos.sh` reports that the
filter is not started and that the listener's port is not locked either.

## Further reading

- [Exposing a listener](/user/policy-cookbook/exposing-a-listener) — the recipe
- [SECURITY.md](https://github.com/ls1intum/phobos/blob/main/SECURITY.md) — the posture this
  section assumes
