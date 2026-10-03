---
title: "Bubblewrap"
sidebar_position: 4
description: "Filesystem isolation through mount namespaces, used by the discovery phase and by nothing else."
---

:::tip[Simple Story]
Bubblewrap sets the bench out before the work is let in.

Papers you did not put on it are not there. Not forbidden, not protected: absent. Nobody can
break a rule about a paper they cannot see.
:::

## What it is

Bubblewrap (`bwrap`) is an unprivileged sandboxing tool. It uses Linux namespaces to give a
process a different view of the system, most importantly a **mount namespace**, in which the
visible filesystem is assembled from scratch. It needs no root, which is what makes it usable
on an ordinary continuous integration (CI) runner.

## Where Phobos uses it, and where it does not

Bubblewrap belongs to the discovery phase alone. A protected run is enforced by Landlock, which
needs no namespace, no privilege and no container flag; the run-phase image does not install
Bubblewrap at all.

That split is the point. The discovery phase has to make a directory **look absent**, because
it is measuring whether the workload notices. Landlock cannot do that: it withholds access
while leaving the name visible. The two phases therefore deny differently, which is the source
of the one surprise on the [Pruning](../pruning.md) page.

## How the discovery phase uses it

`var/tmp/pruning/detect_minimal_fs.sh` builds an argument vector from the candidate
configuration:

| Argument | Effect | What it measures |
| --- | --- | --- |
| `--tmpfs <path>` | the path becomes an empty temporary filesystem | "was this needed at all?" |
| `--ro-bind <path> <path>` | the path is visible and read-only | "is reading it enough?" |
| `--bind <path> <path>` | the path is visible and writable | "does it have to be writable?" |

Mounts are sorted by depth and then by state, hidden first, then read-only, then writable, so
that at one depth the wider mount ends on top. The reference workload itself is bound last,
after every parent mount, into a directory made to exist first, so that no parent mount can
hide it.

Four more options carry reasoning worth keeping:

- **`--tmpfs /` and a separate `--tmpfs /tmp`.** Binding the host's `/tmp` would let the
  sandbox read whatever any other process on the machine left there.
- **`--clearenv`, with an explicit pass-through list.** Nothing reaches the sandbox merely
  because it was set in the shell that started the prune, so a token or a path to a runner
  control file stays outside.
- **`--new-session`.** Without it, and with no seccomp filter, a process inside could push
  characters back into the controlling terminal with `TIOCSTI` and have them run outside.
  Bubblewrap's own guidance asks for one or the other, and this sandbox has no filter.
- **`--unshare-user` is deliberately absent.** What the phase generates has to be the sandbox
  the measurement was made in. Adding an option the prune never ran under would produce a
  policy nobody has tested.

The invocation is an argument vector rather than a string handed to `bash -c`, so a directory
whose name holds a quote, a dollar or a semicolon is a path rather than a command waiting for
its turn.

## Further reading

- [`containers/bubblewrap`](https://github.com/containers/bubblewrap) — the source repository
  and the manual page
- [`namespaces(7)`](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [`mount_namespaces(7)`](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [`user_namespaces(7)`](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [Pruning](../pruning.md) — the phase this tool serves
