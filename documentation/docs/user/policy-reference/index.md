---
title: "Policy Reference"
sidebar_position: 0
description: "How a policy file is read, the twelve sections it may hold, and the rules every section is subject to."
---

:::tip[Simple Story]
One file says what the command may reach. Everything it does not name is refused.

This page covers what is true of the whole file. Each section has a page of its own beside it.
:::

A policy is a file in the style of an `INI` file. It holds sections, and each section holds one
line per entry. Everything from a `#` to the end of a line is a comment, in every section.

```ini title="exercise.cfg"
[read]
/srv/reference-data   # a comment

[limits]
timeout=120
```

Four things are refused rather than ignored, so that a typo cannot silently drop a restriction:
an unknown section, an unknown key in `[limits]`, a malformed line in any section that has a
grammar, and any content before the first section header. Each of them ends the run with
`PHB-EPOLICY`.

## The twelve sections

| Section | What it names |
| --- | --- |
| [`[read]`](read.md) | paths that may be read |
| [`[execute]`](execute.md) | paths whose files may be executed |
| [`[write]`](write.md) | paths whose existing files may be written and shortened |
| [`[create]`](create.md) | paths where regular files and directories may be created |
| [`[delete]`](delete.md) | paths whose files and directories may be deleted |
| [`[create-ipc]`](create-ipc.md) | paths where sockets and named pipes may be created |
| [`[create-symlink]`](create-symlink.md) | paths where symbolic links may be created |
| [`[restructure]`](restructure.md) | paths that may be created in, deleted in, and rearranged |
| [`[connect]`](connect.md) | outbound destinations, by host, port and transport |
| [`[bind]`](bind.md) | local ports that may be listened on |
| [`[accept]`](accept.md) | a listener fronted by an inbound source filter |
| [`[limits]`](limits.md) | the timeout and the five resource limits |

## One section, one right

Each filesystem section grants exactly its own right and nothing beside it. A tree that must be
both readable and executable is named in `[read]` **and** in `[execute]`. A path named in no
section is not listed at all and stays denied.

| Section | Letter | Granted |
| --- | --- | --- |
| `[read]` | `r` | read a file, list a directory |
| `[write]` | `w` | write into an existing file, and shorten it |
| `[execute]` | `x` | execute a file |
| `[create]` | `m` | create regular files and directories |
| `[create-ipc]` | `p` | create sockets and named pipes |
| `[create-symlink]` | `l` | create symbolic links |
| `[restructure]` | `m`, `d`, `f` | create, delete, and move or rename across directories |
| `[delete]` | `d` | delete files and directories |
| — | `i` | `ioctl` on a character or block device |

The letters are the arguments `phobos-landlock` takes, and `--debug` prints them, so this table
is what a verbose log is read with. One letter can stand for more than one kernel right: `r`
carries `READ_FILE`, `READ_DIRECTORY` and, from Landlock version 9, `RESOLVE_UNIX`.

The letter `i` has no policy section, so nothing you write in a configuration file grants it.
The tail flags file is the one place a `--rights=` reaches `phobos-landlock` without a section
behind it; it ships inside the image as `TailPhobos.cfg`, carries the working directory alone
today, and is part of the shipped policy rather than of a task configuration. Creating a device
node has no letter at all and is never granted.

## The rule that catches most hand-written policies

Landlock adds the rights of every rule along a path and can never take one away. A nested entry
granted a **strict subset** of an ancestor's rights therefore states a restriction that will
not hold, and Phobos refuses it:

```
Policy unenforceable: '/opt/toolchain/bin' is granted 'r' but lies beneath '/opt/toolchain',
which is granted the wider 'rx'. Landlock adds the rights of every rule along a path and can
never take one away, so the narrower entry would not hold. (PHB-EPOLICY)
```

Different rights, with neither side a subset of the other, are the ordinary shape of a
workspace and stay allowed. The effective set is then the union, and the union is what the
kernel is handed, so a verbose log never disagrees with what is enforced.

Two consequences follow, and both come up in practice:

- **An entry an ancestor already covers is not redundant.** A base policy that names
  `/usr/bin rx` beneath a `/usr` that is already `rx` grants Landlock nothing new. It decides
  whether a task configuration naming `/usr/bin` in `[read]` alone is accepted: with the base
  row present the entry folds onto it and the run starts, without it the entry is `r` beneath
  an `rx` ancestor and the run stops.
- **Two spellings of one tree are one target.** `/bin` is a symbolic link to `/usr/bin` in the
  run-phase image, and Landlock anchors a rule on the inode, so both entries land on one
  target holding the union of their rights. Phobos resolves every path through its links before
  it compares, and says on standard error where the union is wider than one spelling asked for.

## The example file these pages share

Every section page shows the same file and marks its own section in red, so that reading them
in order walks the file from top to bottom. It is a catalogue rather than a working
configuration, and three of its entries are worth knowing about before you copy one:

- **A stream `[connect]` rule with a concrete port collides with both shipped base policies.**
  Each names three loopback rules with no port, and a section may not mix a wildcard with a
  concrete port on one transport, so the run ends with `PHB-EPOLICY`. A task configuration can
  only widen, so the base policy has to name its loopback ports concretely first.
- **The exact host name needs `--resolver`**, or the network layer refuses the run.
- **The two `udp` rules need a Landlock version 10 kernel**, and `phobos-landlock` refuses them
  on an older one.

## How several files are combined

The model is additive in every dimension. Everything is denied first, and each configuration
only widens:

- Filesystem paths and network rules are unioned.
- For the timeout and each resource limit, the largest value any file names wins, and a zero
  switches that limit off and beats every finite value.

A task configuration therefore cannot narrow below the base, which is why it is trusted input
that the command must not be able to write. The order is the base files first, in sorted order,
then each `--config` in the order given, then the tail flags.

## Line endings are load-bearing

Every text file is stored with a line feed alone. The path sets are read line by line, and a
carriage return at the end of a line becomes part of the path: a read or execute path then
names nothing that exists and is dropped, and a write path is created under the wrong name, so
the run silently loses access the policy granted. The repository's `.gitattributes` keeps it
that way; check with `git ls-files --eol | grep crlf`.

## Further reading

- [Policy Cookbook](/user/policy-cookbook/) — the same sections, one situation at a time
- [phobos.sh](/user/protect-anything/phobos-sh) — how the files are found and combined
- [Policy subsystem](/contributor/subsystems/policy) — the parser and the merge, from the inside
