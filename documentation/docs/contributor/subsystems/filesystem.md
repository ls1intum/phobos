---
title: "Filesystem"
sidebar_position: 2
description: "The layer that turns path sets into Landlock rules, runs the command and counts what it was denied."
---

:::tip[Simple Story]
The last layer in, and the one that starts the work.

It works out which rights each path holds in the end, hands them to the kernel, and then
stays behind to watch what the work was refused.
:::

## What it does

`phobos-filesystem.sh` is the end of the chain. It builds the `--rights=` arguments, starts the
resource layer, runs `phobos-landlock`, and waits for the command so that it can report the
denials.

It is the one layer that runs the command as a **child** rather than replacing itself with
it. Everything else in the chain hands over with `exec`.

## What is in it

| File | Purpose |
| --- | --- |
| `phobos-filesystem.sh` | the layer: arguments, the resource-layer prefix, the run, the denial report |
| `phobos-rights.sh` | the translation from path sets to `--rights=` arguments |
| `phobos-landlock.c` | the sequence of stages, and nothing else |
| `phobos-landlock-options.c` | the command line, read into one object |
| `phobos-landlock-path-rule.c` | one allow-listed path, its rights and its open flags |
| `phobos-landlock-ruleset.c` | the kernel object, the version detection and the operations |
| `phobos-landlock-diagnostics.c` | reporting and giving up |

## The five stages of the translation

`build_path_args` calls each stage plainly, never in a pipe or a process substitution: those
run in a subshell, where an exit on an unenforceable policy would end only the subshell and
leave the run going with no rules at all.

1. **`collect_rights_table`** materialises the changeable paths first, so a path that is read
   or executed as well exists by the time its read row is built and keeps that right. It then
   writes one `letter, resolved path, written path` row per entry. A non-existent read or
   execute path is dropped as a system path absent from this image; a non-existent changeable
   path is kept, so `phobos-landlock` refuses it with a clear message.
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

## What `phobos-landlock` does with them

The program is the sequence of stages and nothing else:

```
parse_arguments
detect_landlock_version      -> refuses a kernel below the minimum, or below what the rules need
report_unenforceable_rights  -> warns about every right this kernel cannot handle
create_ruleset               -> handled filesystem rights, handled network rights, scoping
add_path_rules               -> one LANDLOCK_RULE_PATH_BENEATH per path
add_port_rules               -> one LANDLOCK_RULE_NETWORK_PORT per port and direction
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

## The denial report

The command's standard error passes through `tee` unchanged, and a copy goes to an `awk`
counter in a process substitution. The counts come back over an anonymous pipe.

Nothing is written to a file, so the counts cannot be tampered with from inside the sandbox and
no helper fills a disk. The command inherits neither descriptor, so it sees only its standard
three and can neither feed the counter directly nor keep it alive through a hidden one.
`tee -p` keeps passing the output through should the counter die at its own limits, which only
means no counts.

The wait is bounded and stays below the timeout's kill escalation, because a process the
command left behind can hold its standard error open indefinitely. A run whose counts do not
arrive reports none, and the exit status never changes either way.

## Signals

The layer ignores `SIGTERM` and stays until the command it waits on is gone, so an outer
timeout's escalation reaches the command rather than this layer. The command runs in a subshell
that restores the default disposition and then execs, which is what makes it the process the
escalation finds.

## Known gaps

**A denial count is a text match.** `Permission denied`, `EACCES`, `EROFS` and the two resolver
messages are the whole heuristic. A build that prints one of those phrases for its own reasons
is counted, so the report is a hint rather than a verdict, which is why it never touches the
exit status.

**The `i` right has no section.** `phobos-landlock` accepts the letter, and no configuration
file can produce it. A policy that needs `ioctl` on a device has no way to ask.

## Further reading

- [Landlock](../technologies/landlock.md) — the kernel mechanism and its versions
- [phobos-filesystem.sh](/user/protect-anything/phobos-filesystem-sh) — the same layer, from the
  outside
- [Policy subsystem](policy.md) — where the path sets come from
