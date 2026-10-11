---
title: "Filesystem"
sidebar_position: 2
description: "The layer that turns path sets into Landlock rules and runs the command."
---

:::tip[Simple Story]
The last layer in, and the one that starts the work.

It works out which rights each path holds in the end, hands them to the kernel, and then
stays behind until the work is done.
:::

## What it does

`phobos-filesystem.sh` is the end of the chain. It builds the `--rights=` arguments, starts the
resource layer, runs `phobos-landlock-filesystem-and-networksystem`, and waits for the command so that it can word
a resource limit the command hit.

It is the layer that runs the command itself as a **child**, through the resource layer and
`phobos-landlock-filesystem-and-networksystem`. The timeout layer and the network layer wait
on the rest of the chain as well. Only the policy step, the resource layer and the enforcer
programs hand over with `exec`.

## What is in it

| File | Purpose |
| --- | --- |
| `phobos-filesystem.sh` | the layer: arguments, the report-only supervisor, the resource-layer prefix, the run, the line for a resource limit |
| `phobos-seccomp-filesystem/` | the denial reporter: the wording, the counts and the mirror of Landlock, which the connect guard links too; its main is the report-only supervisor, started only when the network layer is off |
| `phobos-rights.sh` | the translation from path sets to `--rights=` arguments |
| `phobos-landlock-filesystem-and-networksystem.c` | the sequence of stages, and nothing else |
| `phobos-landlock-filesystem-and-networksystem-options.c` | the command line, read into one object |
| `phobos-landlock-filesystem-and-networksystem-path-rule.c` | one allow-listed path, its rights and its open flags |
| `phobos-landlock-filesystem-and-networksystem-ruleset.c` | the kernel object, the version detection and the operations |
| `phobos-landlock-filesystem-and-networksystem-diagnostics.c` | reporting and giving up |

## The five stages of the translation

`build_path_args` calls each stage plainly, never in a pipe or a process substitution: those
run in a subshell, where an exit on an unenforceable policy would end only the subshell and
leave the run going with no rules at all.

1. **`collect_rights_table`** materialises the changeable paths first, so a path that is read
   or executed as well exists by the time its read row is built and keeps that right. It then
   writes one `letter, resolved path, written path` row per entry. A non-existent read or
   execute path is dropped as a system path absent from this image; a non-existent changeable
   path is kept, so `phobos-landlock-filesystem-and-networksystem` refuses it with a clear message.
2. **`fold_table_by_target`** unions the letters of every row naming one resolved target.
   Folding first is what lets the hierarchy check see that two spellings are one tree; without
   it the two rows skip each other as "the same path" and a conflict between them is neither
   merged nor reported.
3. **`report_folded_widenings`** says on standard error where the union is wider than one of
   the spellings asked for, so one entry granting more than another is visible. It only logs,
   and it is called the same way as the rest for the same reason.
4. **`resolve_rights_hierarchy`** refuses an entry whose rights are a strict subset of an
   ancestor's, and gives every other entry the union along its path.
5. **`emit_rights_arguments`** emits one `--rights=` pair per **written** entry, carrying the
   effective rights of its target. It is driven from the collected table rather than the folded
   one: folding is how two spellings are recognised as one tree, and each spelling still needs
   its own rule.

## What `phobos-landlock-filesystem-and-networksystem` does with them

The program is the sequence of stages and nothing else:

```
parse_arguments
detect_landlock_version      -> refuses a kernel below the minimum, or below what the rules need
report_unenforceable_rights  -> warns about the gaps in TRUNCATE, ioctl and scoping, and notes REFER
report_bind_not_closed       -> warns when this kernel cannot close bind, where the policy asked
create_ruleset               -> handled filesystem rights, handled network rights, scoping
add_path_rules               -> one LANDLOCK_RULE_PATH_BENEATH per path
allow_reparenting_everywhere -> with --no-filesystem, REFER granted on / and nothing else
add_port_rules               -> one LANDLOCK_RULE_NETWORK_PORT per port and direction
add_ephemeral_bind_rules     -> the port 0 grants for a kernel-chosen source or listening port
enter_working_directory      -> before the restriction, because the directory may be outside it
apply_restriction            -> PR_SET_NO_NEW_PRIVS, then landlock_restrict_self
exec_command
```

Two details in `add_path_rule` are worth keeping:

- A **changeable** path that is a symbolic link is refused. `O_PATH|O_NOFOLLOW` opens the link
  itself rather than failing, so it has to be rejected here; a rule anchored on a link is at
  best useless and at worst points somewhere the policy never named.
- A path that is **not a directory** loses the rights that only make sense on one, so a rule on
  `/dev/null` keeps read and write and nothing else.

The open flags follow the same reasoning: a rule that may change something is opened with
`O_NOFOLLOW`, and a purely reading rule is not, because system paths legitimately are links.

## The blocked-action report

With the network layer off the layer starts `phobos-seccomp-filesystem` in front of the resource
layer and the enforcer. The supervisor forks before the limits and Landlock exist, so its
supervising half is bound by neither, and the half that goes on becomes the rest of the chain.

The supervising half holds a seccomp user-notification listener on the path calls. It mirrors the
Landlock decision, using the rules on the enforcer's own command line, only to decide whether to
print. It answers every file call with `CONTINUE`, so Landlock alone decides. A race on the path
it read can make a line wrong or missing, and it can never change a decision.

The kernel refuses a second seccomp listener under an existing one, so a run has one supervisor.
With the network layer on that is the connect guard, and `phobos.sh` tells the filesystem layer
so with `--no-own-reporter`.

The group lock's refusals are the one exception to "never decides". The filter that refuses
`setsid`, `setpgid` and foreign-ABI calls hands them to the supervisor, which answers `EACCES`
itself and prints the line. Where it can continue a call, it answers `setsid` and `setpgid`
from its ledger of virtual groups instead (see the timeout page). With no supervisor listening
the kernel refuses them on its own with `ENOSYS`, so a dead supervisor never grants one.

The reporter keeps one line per distinct blocked action and prints at most 100. It quotes a path
the way bash does. It ends with `PHB-ESTATUS` (16) when it cannot read the command's exit status.
A caller that ignores `SIGCHLD` makes that status read as 0. The supervisor therefore sets
`SIGCHLD` back to its default before it forks, and it gives the command the disposition its caller
chose.

## Signals

The layer ignores `SIGTERM` and stays until the command it waits on is gone, so an outer
timeout's escalation reaches the command rather than this layer. The command runs in a subshell
that restores the default disposition and then execs, which is what makes it the process the
escalation finds.

The command's standard error is the layer's own, so a terminal's Ctrl+C, quit or hangup, which
reaches the whole process group, finds no helper between the command and the terminal that it
could kill. Whatever the command writes while it handles the signal, a Python traceback among it,
reaches the terminal.

## Known gaps

**A resource limit is read from a status.** The layer words a CPU or file size limit that the
command hit. It reads the exit status. Status 153 means the file size limit. Status 137 means the
CPU limit, when the processes the layer waited for used the whole CPU budget. A command that exits
with 153 by itself gets the file size line too, because a shell cannot tell the signal from the
number. The process, open file and memory limits leave no such status.

**The `i` right comes from `[ioctl]` only.** The section feeds `ioctl.paths`, which `collect_rights_table` reads
last. Its paths are never materialised, because they name devices. The layer drops one the image lacks, as it does a
read path.

## Further reading

- [Landlock](../technologies/landlock.md): the kernel mechanism and its versions
- [phobos-filesystem.sh](/user/protect-anything/phobos-filesystem-sh): the same layer, from the
  outside
- [Policy subsystem](policy.md): where the path sets come from
