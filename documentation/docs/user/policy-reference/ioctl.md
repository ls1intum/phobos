---
title: "[ioctl]"
sidebar_position: 9
description: "One device path per line, granted the right to issue ioctl calls on the devices beneath it."
---

:::tip[Simple Story]
A key that turns the dials of a machine, not the machine itself.

Being allowed into the room and being allowed to use the controls are two different permissions.
This section grants the controls and nothing else.
:::

## Position in the example policy file

Red marks the section this page documents. Every page in this section shows the same
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

# Devices that may receive ioctl calls, here the pseudo-terminals of the container.
# policy-focus-start
[ioctl]
/dev/pts
# policy-focus-end

[connect]
allow 192.0.2.10:443
allow repo.example.org:443
allow 203.0.113.53:53 udp

[bind]
allow 8080
allow 5353 udp

[accept]
expose 18080 to 8080 from 198.51.100.0/24

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

One path per line, absolute, naming a device node or a directory of them.

```ini
[read]
/dev/pts

[write]
/dev/pts

[ioctl]
/dev/pts
```

## What it grants

| Landlock right | What it permits |
| --- | --- |
| `LANDLOCK_ACCESS_FS_IOCTL_DEV` | an `ioctl` on a character or block device opened beneath the path |

The rule carries the letter `i`. It grants nothing else: opening the device needs `[read]` or `[write]`
on the same path, as the example shows. A pseudo-terminal program, such as Python's `pty` module or
`openpty()`, opens `/dev/ptmx`, issues `ioctl` calls on it and on the slave it opens in `/dev/pts`, and
therefore needs all three sections on `/dev/pts`.

## What enforces it

Landlock enforces it, from version 5. Phobos does not create the path. A base policy drops a path this image
lacks, and an exercise configuration that names one ends the run, as for `[read]`. Where the path appears in no other
section the rule is `--rights=i <path>`; a path named in several sections gets one rule per section, each
carrying the union of the letters.

## Notes

**The right is fixed when the program opens the device.** A descriptor inherited from before the sandbox, or
opened earlier, keeps whatever it had. A few generic commands, such as `FIONREAD`, need no right at all.

**On a kernel below Landlock version 5 the section adds nothing.** The kernel does not restrict `ioctl`
on a device there, and its absence denies nothing. `phobos-landlock-filesystem-and-networksystem` warns about it before the run.

**`/dev/pts` grants every pseudo-terminal of that `devpts` instance.** In a container with its own instance,
as Docker gives it, those are the container's own. Name the directory, not the symbolic link
`/dev/ptmx`: a rule that can change something never follows a final link, so an entry written as a
link ends the run.

**A refused `ioctl` is not reported.** The denial reporter watches file and network calls, not `ioctl`. The
program sees `EACCES`.

**A nested entry adds to its ancestor**, exactly as described on
[`[create-ipc]`](create-ipc.md).

## Further reading

- [`[read]`](read.md) and [`[write]`](write.md): the rights the open itself needs
- [`[create-symlink]`](create-symlink.md): why a changeable rule refuses to follow a link
