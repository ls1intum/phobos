---
title: "What is Phobos"
sidebar_position: 1
description: "What Phobos is, what it can put in a sandbox, and how this documentation is organised."
---

:::tip[Simple Story]
Somebody hands you a program and asks you to run it. You have no reason to trust it, and you
have every reason to keep it away from the rest of the machine.

Picture a workshop with one bench. Before the work starts, someone walks round the room and
takes away everything the job was never shown to need: the drawers stay in place, they simply
do not open. The telephone reaches three numbers and no others. A clock on the wall ends the
session whether or not the work is finished. Phobos is that room, built by the operating system
before the program is let in.
:::

Phobos runs an arbitrary command with only the access that command was shown to need. It is not
tied to one language, one build tool or one kind of program: `phobos.sh -- <command>` takes
whatever you give it, and the policy language names paths, ports and limits rather than
anything about the program inside.

Grading a student submission for a programming exercise is the use case Phobos was written for,
and it is one use case among several. An untrusted build step in a pipeline, a data job that
should reach one directory, a third-party tool you would rather not let phone home: each is the
same problem, and each gets the same two phases.

## The two phases

**Resource discovery, offline.** Phobos runs a reference workload repeatedly, hiding one
directory at a time behind an empty overlay, and observes whether the run still does what it
should. A directory whose absence changes nothing was never needed and stays hidden; one whose
absence breaks the run is restored, read-only first and writable only where that is not enough.
The walk is top-down, so an unused subtree is dropped in one step rather than file by file. The
result is a path set: every path the run needs, with the access mode it needs.

**Sandbox application, at run time.** The command runs under a Landlock ruleset that grants
exactly the rights the policy names on those paths. Every other path is denied, though it stays
visible by name. Outbound connections are supervised from outside the process, a timeout and
resource limits bound the run, and the container around it supplies the caps Phobos cannot set
for itself.

The point of the split is that the expensive, fragile part happens once per runtime
environment, offline, and a protected run only applies a fixed configuration.

## The four layers

| Layer | Mechanism | What it bounds |
| --- | --- | --- |
| Filesystem | Landlock, applied by `phobos-landlock` | which paths the command may read, write, execute, create or delete |
| Network | a seccomp connect guard, an HAProxy egress broker and inbound filter, and Landlock port rules | which hosts and ports the command may reach, and which local ports it may listen on |
| Timeout | GNU `timeout` plus a seccomp process-group lock | how long the whole run may take |
| Resources | rlimits | how much memory, how many processes and open files, how large a file and how much processor time |

Each layer can be switched off on its own, and each can be run on its own over a policy. None
of them needs a privilege, a capability or a container flag: Landlock, seccomp and rlimits are
all self-imposed by the unprivileged process before it hands over to the command.

## What Phobos is not

Phobos is the operating-system layer, and no single layer is the whole story. It does not
reach inside a language runtime, and it does not replace the container it runs in. The page
[What does Phobos not protect against](what-does-phobos-not-protect-against.md) says where the
boundary ends, and the reasoning behind the split is in
[SECURITY.md](https://github.com/ls1intum/phobos/blob/main/SECURITY.md).

## Where to go next

The rows follow the order of the sidebar, so reading straight down is the same as working
through the guide from top to bottom.

| If you want to | Read |
| --- | --- |
| Know what a command is stopped from doing | [What does Phobos protect against](what-does-phobos-protect-against.md) |
| Know where the boundary ends, and what your deployment still has to do | [What does Phobos not protect against](what-does-phobos-not-protect-against.md) |
| Put a command in the sandbox for the first time | [phobos.sh](../protect-anything/phobos-sh.md) |
| Understand one layer on its own | [phobos-filesystem.sh](../protect-anything/phobos-filesystem-sh.md), [phobos-network.sh](../protect-anything/phobos-network-sh.md), [phobos-timeout.sh](../protect-anything/phobos-timeout-sh.md), [phobos-resources.sh](../protect-anything/phobos-resources-sh.md) |
| Write a policy for one concrete situation | [Policy Cookbook](/user/policy-cookbook/) |
| Look up a single policy section | [Policy Reference](/user/policy-reference/) |
| Work out what a message is telling you | [Troubleshooting](../troubleshooting.md) |
| Understand how Phobos works internally | The [Contributor Guide](/contributor/how-can-you-contribute) |

## Licence

Phobos is licensed under the MIT Licence. See
[LICENSE](https://github.com/ls1intum/phobos/blob/main/LICENSE) for details.
