---
title: "Landlock"
sidebar_position: 1
description: "The unprivileged kernel sandbox behind the filesystem boundary and the port rules, and the versions its rights arrived in."
---

:::tip[Simple Story]
A process asks the kernel to take its own privileges away, and the kernel agrees.

Nothing is mounted, nothing is hidden, nothing is copied. What changes is the answer the kernel
gives the next time this process, or anything it starts, asks to open something.
:::

## What it is

Landlock is a stackable Linux Security Module that lets any process restrict itself and its
future children. A policy is a set of access rights tied to a file hierarchy, configured and
enforced through three system calls:

| Call | What it does |
| --- | --- |
| `landlock_create_ruleset` | creates a ruleset, declaring which rights it **handles** |
| `landlock_add_rule` | adds one rule, tying rights to a path or a port |
| `landlock_restrict_self` | enforces the ruleset on the calling thread |

It needs no privilege. A task may always restrict itself further, which is why the run phase
needs no root step, no capability and no container flag. `PR_SET_NO_NEW_PRIVS` is required
beforehand, and Phobos sets it, which closes the setuid route out of the sandbox at the same
time.

## How Phobos uses it

`phobos-landlock` reads one `--rights=LETTERS PATH` pair per policy entry, opens each path with
`O_PATH`, and adds one `LANDLOCK_RULE_PATH_BENEATH` rule:

| Letter | Rights granted |
| --- | --- |
| `r` | `READ_FILE`, `READ_DIRECTORY`, and `RESOLVE_UNIX` from version 9 |
| `w` | `WRITE_FILE`, and `TRUNCATE` from version 3 |
| `x` | `EXECUTE` |
| `m` | `MAKE_REGULAR_FILE`, `MAKE_DIRECTORY` |
| `p` | `MAKE_SOCKET`, `MAKE_NAMED_PIPE` |
| `l` | `MAKE_SYMBOLIC_LINK` |
| `f` | `REFER`, from version 2 |
| `d` | `REMOVE_FILE`, `REMOVE_DIRECTORY` |
| `i` | `IOCTL_DEVICE`, from version 5 |

`MAKE_CHARACTER_DEVICE` and `MAKE_BLOCK_DEVICE` stay in the handled set and are granted by no
letter, so creating a device node is denied rather than left unregulated.

Port rules are `LANDLOCK_RULE_NETWORK_PORT`, one per port and direction, and scoping is applied
to every ruleset from version 6.

## The version ladder

`core/phobos-landlock-ruleset.h` names the first version that carries each right. A right the
running kernel does not know is **not handled at all**, so it is free on every path, including
the ones the policy calls read-only.

| Version | What it brought | What Phobos does without it |
| --- | --- | --- |
| 1 | the filesystem rights | nothing runs below this |
| 2 | `REFER` | notes that every rename across directories is refused with `EXDEV` |
| 3 | `TRUNCATE` | warns that a file on a read-only path can still be emptied |
| 4 | the port rights for streams | refuses a policy that names a port |
| 5 | `IOCTL_DEVICE` | warns that `ioctl` on a device is unrestricted on every allowed path |
| 6 | scoping for signals and abstract sockets | warns that both reach outside the sandbox |
| 9 | `RESOLVE_UNIX` | grants nothing extra; a pathname socket outside the domain is not gated |
| 10 | the port rights for datagrams | refuses a policy that names a datagram rule |

Three of those are warnings and two are refusals, and the difference is deliberate. A missing
right that leaves something **free** is a hole, so it is said out loud on every run rather than
only under `--debug`. A missing right the policy **named** is a promise Phobos cannot keep, so
the run stops. `--minimum-landlock-version` turns any of the warnings into a refusal.

The missing `REFER` is the one case that points the other way: without it the kernel denies
every rename across directories rather than leaving it free. That breaks a build loudly instead
of weakening the sandbox quietly, so it is reported as a note.

Where the kernel offers a version higher than the build enumerates, `phobos-landlock` warns
that rights added after that point are not restricted.

## Three properties worth knowing before writing a policy

**Rights are unioned along a path, never subtracted.** A nested rule can only add. A policy
declaring fewer rights on a nested path states a restriction that will not hold, which is why
Phobos refuses it rather than passing it to the kernel.

**A rule is anchored on the inode, not on the spelling.** `/bin` and `/usr/bin` are one tree on
a merged-usr system, so Phobos resolves every path through its symbolic links before it
compares.

**A subtree is granted whole.** There is no way to carve an exception inside a granted
hierarchy, and no way to make a denied path invisible: Landlock withholds access rather than
building a new view of the filesystem.

## Composing two rulesets

Landlock rulesets stack by intersection, and Phobos relies on that. The network layer applies a
ruleset created with `--no-filesystem`, which handles no filesystem right and carries the port
rules alone; the filesystem layer later applies its own, which handles the filesystem and
carries no port rule. Neither can widen the other.

## Further reading

- [Landlock: unprivileged access control](https://docs.kernel.org/userspace-api/landlock.html) —
  the kernel documentation
- [`landlock(7)`](https://man7.org/linux/man-pages/man7/landlock.7.html) — the manual page, with
  the application binary interface (ABI) version each right arrived in
- [`landlock_create_ruleset(2)`](https://man7.org/linux/man-pages/man2/landlock_create_ruleset.2.html),
  [`landlock_add_rule(2)`](https://man7.org/linux/man-pages/man2/landlock_add_rule.2.html),
  [`landlock_restrict_self(2)`](https://man7.org/linux/man-pages/man2/landlock_restrict_self.2.html)
- [landlock.io](https://landlock.io/) — the project page
- [`prctl(2)`](https://man7.org/linux/man-pages/man2/prctl.2.html) — `PR_SET_NO_NEW_PRIVS`
