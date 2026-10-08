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
| `2` | no `PHB-` code | a script was called the wrong way |
| `11` | `PHB-EPOLICY` | the policy is invalid, or cannot be enforced as written |
| `14` | `PHB-ETIMEOUT` | the run passed its timeout and was stopped |
| `15` | `PHB-ERUNTIME` | something Phobos needs is missing or cannot be started |
| `16` | `PHB-ESTATUS` | the command ran, but its exit status could not be read, so the run cannot say whether it succeeded |
| `125` | no `PHB-` code | `phobos-landlock-filesystem-and-networksystem`, the connect guard or the group lock refused to set the sandbox up |
| `127` | no `PHB-` code | the command itself could not be executed |
| anything else | no `PHB-` code | the command's own status. Phobos did not stop the run. |

A signal sent to `phobos.sh` (`SIGTERM`, `SIGHUP`, `SIGINT` or `SIGQUIT`) is passed on to the
command, and `phobos.sh` then ends with 128 plus the signal's number once the layers have cleaned
up. A command that ignores the signal goes on until its time limit. `SIGKILL` cannot be passed
on, so a caller that must stop a run at once kills the whole process group. A run whose clean-up
fails ends with `15` even if the command succeeded.

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

Name a concrete port. Only a host that is exactly one loopback address can leave it out. Phobos
refuses a range such as `127.0.0.1/1` and a name such as `127.evil.example` too, and names the file
and the line.

### A loopback wildcard sits beside a concrete port

This is not an error. The run starts, and the network layer says on standard error:

```
network: '127.0.0.1:*' names no port; the Landlock network layer stays off, and the connect guard filters this run
network: the tcp ports 443 named beside it get no Landlock rule either, since Landlock cannot keep loopback open on every port and close the rest, so the connect guard alone enforces them, by host and port
```

**The wildcard is usually not yours.** Both shipped base policies name three loopback rules
with no port, `allow 127.0.0.1:*`, `allow [::1]` and `allow localhost`, so any task
configuration that adds a stream rule with a concrete port ends up beside them. Landlock
cannot keep loopback open on every port and close the rest. The port you named therefore has
no kernel rule, and the connect guard enforces it alone, by host and port, while the network
layer is on. The second line names these ports, so you see a port you expected the kernel to
hold.

The two transports are separate. On every kernel the guard alone holds a udp rule that names a
port beside a udp loopback wildcard, so it needs no Landlock version 10. The same rule on its
own does need it.

### A path is relative, has a wildcard or does not exist

```
Policy invalid: 'data' in [read] is not an absolute path. Write the whole path from /, because ~,
variables, quotes and names relative to a directory are not expanded. Found in 'exercise.cfg',
line 3. (PHB-EPOLICY)
```

```
Policy invalid: '/usr/lib/jvm/*' in [read] holds a wildcard character, and a path is taken as
written, so it would name the one entry with that literal name and not the files it looks like it
matches. Name the directory or the file itself. Found in 'exercise.cfg', line 4. (PHB-EPOLICY)
```

```
Policy invalid: '/srv/reference-dta' in [read] does not exist on this system, so the rule would
grant nothing. Check the spelling, or remove the line if the path is not needed here. Found in
'exercise.cfg', line 5. (PHB-EPOLICY)
```

Write the full path from `/`, name the directory instead of a pattern, and check the spelling.
The missing-path check applies to `[read]` and `[execute]` in a task configuration. The sections
that change things create a missing path, and the shipped base policies are exempt.

### A configuration file is not the text it should be

```
Policy invalid: this line contains a carriage return, which a Windows line ending leaves at its
end and which would become part of the value. Save the file with LF line endings. Found in
'exercise.cfg', line 1. (PHB-EPOLICY)
```

The same refusal family covers a byte order mark and a NUL byte, which name the file alone. It
covers a resource limit with more than 18 significant digits and a timeout with more than 15
significant digits in its seconds part. It covers a `--config` that is a directory, a link to
nothing, not a regular file or not readable. The message says which. See
[what Phobos refuses in a file](policy-reference/index.md#what-phobos-refuses-in-a-file-and-how-it-says-so).

### A `[bind]` rule names an address

```
Policy invalid: '127.0.0.1:8080' in [bind] is not a bare port; [bind] takes only a port number,
because Landlock enforces a bind by port and cannot narrow to a local address. Name the port
alone, and govern a listener's reachability with [accept]. Found in 'exercise.cfg', line 12.
(PHB-EPOLICY)
```

Every refusal that concerns one line of a configuration ends with the file and the line.

Write the port alone, and govern reachability with [`[accept]`](policy-reference/accept.md).

### A changeable path is a symbolic link with no target

```
Policy invalid: '/var/tmp/workspace' is a symbolic link with no target, so materialising it
would write wherever it points. (PHB-EPOLICY)
```

Point the link at something that exists, or name the real path.

### No base policy was found

```
Policy invalid: no Base*.cfg beside phobos-policysystem.sh, so there is no sandbox to apply;
refusing to build a policy. (PHB-EPOLICY)
```

You are running from a checkout rather than from the run-phase image. The shipped base
configurations live in `core/config/`, and `phobos-policysystem.sh` looks for them beside itself.
Build the image. `--no-restriction` (`-nr`) runs the command with no sandbox at all. It is a debugging switch, it is refused together with `--config`, and it does not make a checkout run the sandbox.

### The specification directory lies under a write path

```
Policy unenforceable: the specification directory '/var/tmp/phobos-spec.XXXXXX' lies beneath
the write path '/var/tmp', so the graded command could rewrite the connect policy or the
record the clean-up acts on. (PHB-EPOLICY)
```

The message says `graded command`, which is the sandboxed command whatever it happens to be. The
record the clean-up acts on is the file that names the hosts file whose lines the run added.
Move the specification with `--spec-parent`, or name a subdirectory rather than `/var/tmp`
itself in the write sections.

## Exit status 125: the enforcer refused to set the sandbox up

These come from `phobos-landlock-filesystem-and-networksystem` or the connect guard rather than from a shell layer, so they
carry the program's own prefix and none of the `PHB-` codes.

### A datagram rule on a kernel below Landlock version 10

```
[phobos-landlock-filesystem-and-networksystem] UDP network rules require Landlock version 10
```

A `udp` rule that names a port is refused rather than left unenforced. Either run on a kernel
that carries the version 10 rights or drop the rule. A `udp` `[connect]` rule beside a `udp`
loopback rule with no port is the exception: the guard alone holds it, on any kernel. A `udp`
`[bind]` row of port 0 never stops a run either. Below version 10 the enforcer cannot close UDP
bind, so it warns and leaves the bind open. The same status and prefix carry every other refusal
from that program, `--minimum-landlock-version` among them.

## PHB-ERUNTIME: something Phobos needs is missing

### The connect guard is missing

```
The connect guard '/var/tmp/opt/core/phobos-seccomp-networksystem' is missing or not executable;
refusing to run without connect supervision. (PHB-ERUNTIME)
```

The four compiled programs (the enforcer, the connect guard, the report-only supervisor and the
group lock) are built inside the run-phase image and never committed. A bare checkout therefore
cannot run. Build the image.

### The process-group lock is missing

```
The group lock '/var/tmp/opt/core/phobos-seccomp-timeoutsystem' is missing or not executable; refusing
to run a timed command that could escape the timeout with setsid. (PHB-ERUNTIME)
```

Same cause, same fix.

### An exact host name without a resolver

```
The [connect] allow-list names an exact host, which the egress broker binds by resolving it,
but no resolver was given; pass --resolver <ip[:port]>. Refusing rather than run without
host-name enforcement. (PHB-ERUNTIME)
```

Give the run a resolver, or name the host's address or address range instead.

### `PATH` names no absolute directory

```
PATH '.:bin' names no absolute directory, and an empty PATH is searched as the current
directory; start Phobos with a PATH of absolute directories. (PHB-ERUNTIME)
```

Every entry point keeps only the absolute entries of `PATH` before it runs anything, and never
adds one. Start Phobos with a `PATH` of absolute directories. Name a command that ran before
only because `.` was on `PATH` by its path, as in `./gradlew test`.

### `realpath` is the wrong one

```
Runtime unusable: realpath does not take --canonicalize-missing --no-symlinks, so a policy's
paths cannot be canonicalised. GNU coreutils is what provides it. (PHB-ERUNTIME)
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

### A `Phobos Security Error` line

```
Phobos Security Error: the program tried to illegally read the File '/etc/shadow' but was blocked by Phobos.
```

With the network layer off, or the filesystem layer on its own, the layer's report-only supervisor
prints one such line for each distinct blocked action it can attribute with certainty. A run
prints at most 100. The supervisor is exact where it speaks and silent where it is in doubt, so a
run without a line can still have been refused something. When it cannot report, it says so in a
notice that names what goes unreported. With the network layer on, the connect guard is the one
supervisor, and these lines do not appear. The
[filesystem layer page](protect-anything/phobos-filesystem-sh.md#reporting-what-the-layer-blocks)
describes what the lines cover.

### The command's exit status could not be read

If the supervisor cannot read the command's own exit status, the run ends with `PHB-ESTATUS` and
status 16 instead of reporting a success it cannot vouch for. The supervisors set `SIGCHLD` back to
its default before they fork, so a caller that ignored `SIGCHLD` cannot cause this on its own.
The message is:

```
the command's exit status could not be read, so the run cannot say whether it succeeded (PHB-ESTATUS)
```

A grader that treats every non-zero status as a failure needs no change. A grader that lists
Phobos's own statuses must add 16.

## A server cannot listen, or a warning says bind stays open

Bind is closed unless a `[bind]` row opens it, so a command that starts a server without one
fails with a permission error on `bind` or `listen`. Add the port to `[bind]`, or `allow 0` for a
port the kernel chooses. The shipped Java policy already grants port 0 and nothing more.

A kernel too old to close bind gets a warning on standard error instead of a refusal:

```
[phobos-landlock-filesystem-and-networksystem] warning: Landlock version 3 cannot close TCP bind
(that needs version 4); a command can still bind and listen on any TCP port, so the container's
network isolation is the only boundary there. Pass --minimum-landlock-version 4 to refuse such a
kernel instead.
```

The run goes on, because refusing would stop every run on that kernel. The UDP warning is the same
with version 10. Put `--minimum-landlock-version` in the tail flags to refuse such a kernel
instead.

## A run with no `--config` reaches nothing on the network

A run given no `--config` is not a grading run, so Phobos drops every `[connect]`, `[bind]` and
`[accept]` rule the base granted, loopback included. A Gradle build then cannot reach its own
daemon. Pass the exercise configuration, or `--no-networksystem-restriction` to find out whether the
network layer is the cause.

## Which layer refused?

Switch one layer off at a time. The timeout, network and resource layers drop out of the chain
when disabled. The filesystem layer stays: with `-nfr` it still runs the command and counts
denials, and only Landlock is left out. Each is recorded on standard error, so the log says what
was off.

```bash
${PHOBOS_HOME}/phobos.sh --no-filesystem-restriction -- <command>    # -nfr
${PHOBOS_HOME}/phobos.sh --no-networksystem-restriction -- <command> # -nnr
${PHOBOS_HOME}/phobos.sh --no-timeoutsystem-restriction -- <command>       # -ntr
${PHOBOS_HOME}/phobos.sh --no-resourcesystem-restriction -- <command>     # -nrr
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
maps that name in `/etc/hosts` before the filesystem layer makes `/etc` read-only, so the
command's own lookup succeeds without a query: to a loopback placeholder for a stream rule, and to
the real addresses the name had at the start for a `udp` rule, which a name held by both kinds of
rule gets instead of the placeholder. A name the policy does not mention
gets no such entry.

## A server's first bytes arrive five seconds late

Where a stream `[connect]` rule names a host, the connect guard hands every allowed stream
connection to the egress broker, loopback ones included. On a port a name rule names, the broker
reads the Transport Layer Security (TLS) host name before it decides. A server that speaks
first, as SMTP, MySQL or SSH do, gets nothing from its client there, so the broker waits out its
five-second inspection delay before an address rule lets the connection through. A connection
to any other port goes through at once. Serve the program on a port no name rule names.

## A `udp` rule that names a host refuses the run

The network layer resolves such a name once, before the command starts, and ends the run with
`PHB-ERUNTIME` and one of these messages when it cannot:

- `A udp [connect] rule names a host (...) ... no resolver was given`: pass `--resolver <ip[:port]>`.
- `A udp [connect] host name could not be resolved through ...`: the line above it from the
  guard says why, for example that the name has no address, the resolver did not answer in
  time, or the answer was truncated or held no record of that name. The lookup needs a networked
  container, so it cannot succeed under `--network none`.
- `/etc/hosts maps '...' to a different set of addresses than this run needs`: the file already
  names the host with other addresses, for example from the image or another run that resolved
  it differently. Remove the stale line, or let that run end first.
- `Resolving the udp [connect] host names gives N rules, and the connect guard keeps 256`: name
  fewer hosts or ports. More than 64 names to resolve is refused by the guard in the same way.

## A datagram send is refused with `Permission denied`

The connect guard makes every datagram connect and every send that names a destination itself, and
refuses what it cannot do faithfully. Besides a destination the allow-list does not name, it refuses a send on a socket it
did not create, `sendmsg` and `sendmmsg` on any socket that is not a datagram socket it holds
(a TCP or UNIX socket included), a send with ancillary data, and a send on a socket that was
never bound unless a `udp` rule or a `[bind]` row of port 0 for `udp` grants an ephemeral bind.
A datagram of more than 65,535 bytes answers `Message too long`. Run with `--debug` to see which of these the
guard reports.

## A rename fails with `EXDEV`

The REFER right is what Landlock requires for a rename or a hard link across directories, and
it is granted only by [`[restructure]`](policy-reference/restructure.md). On a kernel below
Landlock version 2 the right does not exist at all, and every such rename is refused;
`phobos-landlock-filesystem-and-networksystem` reports that as a note before the run.

## Further reading

- [phobos.sh](protect-anything/phobos-sh.md): the options named above
- [Policy Reference](/user/policy-reference/): what each section means
- [What does Phobos not protect against](phobos/what-does-phobos-not-protect-against.md):
  where a failure is not Phobos's to fix
