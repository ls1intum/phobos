---
title: "Troubleshooting"
sidebar_position: 5
description: "What each Phobos message and exit status means, and what to do next."
---

:::tip[Simple Story]
Every refusal says which layer refused and why.

The first question is never "what is broken" but "which layer said no", and the exit status
answers it before you read a line of the log.
:::

Standard output carries the command's own output and nothing else. Every message from Phobos
goes to standard error, so whatever reads the run can take one stream and a person the other.

## Start from the exit status

| Status | Prefix | Meaning |
| --- | --- | --- |
| `2` | — | a script was called the wrong way |
| `11` | `PHB-EPOLICY` | the policy is invalid, or cannot be enforced as written |
| `14` | `PHB-ETIMEOUT` | the run passed its timeout and was stopped |
| `15` | `PHB-ERUNTIME` | something Phobos needs is missing or cannot be started |
| `125` | — | `phobos-landlock` or the connect guard refused to set the sandbox up |
| `127` | — | the command itself could not be executed |
| anything else | — | the command's own status. Phobos did not stop the run. |

`PHB-EDENY` carries no status of its own. It is a count of lines in the command's own standard
error that look like denials, printed as a hint, and it never changes the exit status.

## PHB-EPOLICY: the policy cannot be enforced as written

These end the run before the command starts with exit status 11. Every one of them is a
refusal rather than a warning, because the alternative is a sandbox that reads stricter than it
is. Each message is quoted here exactly as the run prints it, so the text can be searched for
in a log.

### A nested path is granted fewer rights than its ancestor

```
Policy unenforceable: '/opt/toolchain/bin' is granted 'r' but lies beneath '/opt/toolchain',
which is granted the wider 'rx'. Landlock adds the rights of every rule along a path and can
never take one away, so the narrower entry would not hold. (PHB-EPOLICY)
```

Landlock can only add rights further down a path. Either grant the nested path at least what
its ancestor holds, or stop naming it: it already inherits the ancestor's rights. Different
rights, with neither side a subset, are allowed and produce the union.

### An external host names no port

```
Policy unenforceable: 'repo.example.org' names a host with no port. Landlock enforces ports,
not hosts, so an external host with no port cannot be enforced. Name a concrete port, and rely
on a no-network container as the outer boundary. (PHB-EPOLICY)
```

Name a concrete port. Only a loopback host may leave it out.

### A loopback wildcard sits beside a concrete port

```
Policy unenforceable: '127.0.0.1:*' names no port, so Landlock cannot express it, while other
rules do name one. A half-enforced network policy would look stricter than it is. (PHB-EPOLICY)
```

Mixing them would leave one rule kernel-enforced and the other not, which reads stricter than
it is.

**The wildcard is usually not yours.** Both shipped base policies name three loopback rules
with no port, `allow 127.0.0.1:*`, `allow [::1]` and `allow localhost`, so any task
configuration that adds a stream rule with a concrete port collides with them. A task
configuration can only widen, so it cannot take the wildcard away: reaching an external host
over a stream needs the base policy for that runtime environment to name its loopback ports
concretely.

A datagram rule does not collide, because the two transports are judged apart, and neither
does a `[bind]` rule.

### A `[bind]` rule names an address

```
Policy invalid: '127.0.0.1:8080' in [bind] is not a bare port; [bind] takes only a port number,
because Landlock enforces a bind by port and cannot narrow to a local address. Name the port
alone, and govern a listener's reachability with [accept]. (PHB-EPOLICY)
```

Write the port alone, and govern reachability with [`[accept]`](policy-reference/accept.md).

### A changeable path is a symbolic link with no target

```
Policy invalid: '/var/tmp/workspace' is a symbolic link with no target, so materialising it
would write wherever it points. (PHB-EPOLICY)
```

Point the link at something that exists, or name the real path.

### No base policy was found

```
Policy invalid: no Base*.cfg beside phobos-policy.sh, so there is no sandbox to apply;
refusing to build a policy. (PHB-EPOLICY)
```

You are running from a checkout rather than from the run-phase image. The shipped base
configurations live in `core/config/`, and `phobos-policy.sh` looks for them beside itself.
Build the image, or pass `--allow-unsandboxed` where an unprotected run is what you meant.

### The specification directory lies under a write path

```
Policy unenforceable: the specification directory '/var/tmp/phobos-spec.XXXXXX' lies beneath
the write path '/var/tmp', so the graded command could rewrite the connect policy or the
clean-up's process-id files. (PHB-EPOLICY)
```

The message says `graded command`, which is the sandboxed command whatever it happens to be.
Move the specification with `--spec-parent`, or name a subdirectory rather than `/var/tmp`
itself in the write sections.

## Exit status 125: the enforcer refused to set the sandbox up

These come from `phobos-landlock` or the connect guard rather than from a shell layer, so they
carry the program's own prefix and none of the `PHB-` codes.

### A datagram rule on a kernel below Landlock version 10

```
[phobos-landlock] UDP network rules require Landlock version 10
```

A `udp` rule is refused rather than left unenforced. Either run on a kernel that carries the
version 10 rights or drop the rule. The same status and prefix carry every other refusal from
that program, `--minimum-landlock-version` among them.

## PHB-ERUNTIME: something Phobos needs is missing

### The connect guard is missing

```
The connect guard '/var/tmp/opt/core/phobos-connect-guard' is missing or not executable;
refusing to run without connect supervision.
```

The three compiled programs are built inside the run-phase image and never committed. A bare
checkout therefore cannot run. Build the image.

### The process-group lock is missing

```
The group lock '/var/tmp/opt/core/phobos-pgroup-lock' is missing or not executable; refusing
to run a timed command that could escape the timeout with setsid.
```

Same cause, same fix.

### An exact host name without a resolver

```
The [connect] allow-list names an exact host, which the egress broker binds by resolving it,
but no resolver was given; pass --resolver <ip[:port]>.
```

Give the run a resolver, or name the host's address or address range instead.

### `realpath` is the wrong one

```
Runtime unusable: realpath does not take --canonicalize-missing --no-symlinks, so a policy's
paths cannot be canonicalised. GNU coreutils is what provides it.
```

The BSD and BusyBox versions do not take those options. Without them every path would fall
through to a spelling comparison, so two names for one tree would look like two trees and a
narrowing rule would go unnoticed. Install GNU coreutils.

## PHB-ETIMEOUT: the run passed its limit

```
Timed out after 120s. (PHB-ETIMEOUT)
```

The run reached its `[limits]` timeout and the whole process group was signalled, escalating to
`SIGKILL` five seconds later for a command that ignored `SIGTERM`.

A run is labelled this way only where GNU `timeout`'s status says so **and** the run lasted at
least its limit. A command's own exit status 124, and a `SIGKILL` from the out-of-memory
killer, pass through unchanged, so a run that ends with 137 and no `PHB-ETIMEOUT` was killed by
something other than the timeout.

## PHB-EDENY: the command was refused something

```
Sandbox denials: network=3, filesystem=12. (PHB-EDENY)
```

The filesystem layer counted lines in the command's standard error matching
`Permission denied`, `EACCES` or `EROFS`, and the resolver and unreachable-network messages.
It is a hint, not a verdict: a build that prints one of those phrases for its own reasons is
counted too, and the exit status never changes.

Where the count is high and the run failed, the next step is `--debug`, which prints the whole
effective policy each layer was given.

## Which layer refused?

Switch one layer off at a time. A disabled layer is left out of the chain rather than entered
and skipped, and each is recorded on standard error, so the log says what was off.

```bash
${PHOBOS_HOME}/phobos.sh --no-filesystem-restriction -- <command>    # -nfr
${PHOBOS_HOME}/phobos.sh --no-networksystem-restriction -- <command> # -nnr
${PHOBOS_HOME}/phobos.sh --no-runtime-restriction -- <command>       # -ntr
${PHOBOS_HOME}/phobos.sh --no-resources-restriction -- <command>     # -nrr
```

Each layer can be run on its own over a configuration instead, which is the other direction of
the same question:

```bash
${PHOBOS_HOME}/phobos-filesystem.sh --config exercise.cfg -- <command>
```

## A pruned policy fails a run that passed its prune

This one has a specific cause, and it is the first thing to check.

The two phases do not deny in the same way. While pruning, a hidden directory is an empty,
**writable** temporary filesystem, because Landlock cannot make a path look empty. During a
protected run, a path the policy does not name is refused with `EACCES`.

A tool that only needs some writable scratch directory therefore passes its prune with that
directory hidden, since the empty overlay was writable, and is refused at run time, since the
policy never named it. Give the tool its scratch directory explicitly.

## The command cannot resolve a name

A run under `--network none` has no resolver at all, and the connect guard refuses a datagram
to one in any case unless `[connect]` names it. Where the policy names an exact host, Phobos
maps that name to a loopback placeholder in `/etc/hosts` before the filesystem layer makes
`/etc` read-only, so the command's own lookup succeeds without a query. A name the policy does
not mention gets no such entry.

## A rename fails with `EXDEV`

The REFER right is what Landlock requires for a rename or a hard link across directories, and
it is granted only by [`[restructure]`](policy-reference/restructure.md). On a kernel below
Landlock version 2 the right does not exist at all, and every such rename is refused;
`phobos-landlock` reports that as a note before the run.

## Further reading

- [phobos.sh](protect-anything/phobos-sh.md) — the options named above
- [Policy Reference](/user/policy-reference/) — what each section means
- [What does Phobos not protect against](phobos/what-does-phobos-not-protect-against.md) —
  where a failure is not Phobos's to fix
