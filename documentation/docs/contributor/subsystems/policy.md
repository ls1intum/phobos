---
title: "Policy"
sidebar_position: 1
description: "The one parser: how a configuration becomes the specification every layer reads."
---

:::tip[Simple Story]
One program reads the configuration, and nothing else ever does.

Every layer is handed a directory of small files rather than a file it has to understand, so
two layers can never disagree about what the policy said.
:::

## What it does

`phobos-policy.sh` discovers the base policy, parses every configuration, merges them and
writes one file per part into a directory the caller owns. It is the only parser: a layer
running on its own over `--config` calls this program too, so no layer ever reads a
configuration file itself.

```
phobos-policy.sh [--debug] --spec-dir <dir> [--tail-flags-file <file>] [--config <file>]...
```

The caller creates and owns the directory and removes it when the run ends. This program only
writes into it, using a scratch subdirectory of it for its own temporary files, so everything
it makes is removed with the directory rather than left in `/tmp`, which the policy itself
usually makes writable.

## What is in it

| File | What it holds |
| --- | --- |
| `phobos-policy.sh` | the program: base discovery, the merge, the checks, the write |
| `phobos-policy-parse.sh` | one configuration in, the parsed state and the per-right files out |
| `phobos-rights.sh` | a parsed policy to the `--rights=` arguments `phobos-landlock` takes |
| `phobos-network-args.sh` | `[connect]` and `[bind]` to the Landlock port rules, and the refusals |
| `phobos-spec-dir.sh` | the specification directory, its marker, and its lifetime |
| `phobos-paths.sh` | the two canonical forms a path is compared in |
| `phobos-time.sh` | how a timeout is spelled, merged and compared |
| `phobos-constants.sh` | the exit statuses and the other shared numbers |
| `phobos-log.sh` | reporting, and the denial counter |
| `phobos-common.sh` | the aggregate every caller sources, which sources the eight above |

`phobos-common.sh` has no include guard on purpose: sourcing it has to keep resetting
`PHB_DEBUG_ENABLED`, so that the environment can never switch debugging on.

## Base discovery

Every `Base*.cfg` beside the script, in the order the shell sorts a glob. Two refusals guard
it, and both are refusals rather than skips:

- **No match at all** ends the run: there is no sandbox to apply, so building a policy would
  mean running the command unprotected.
- **A name the glob matched that is not a readable file** ends the run too. Skipping it would
  build a policy from the bases that happened to be readable, which is a narrower sandbox
  reported as a working one.

## The merge

`fold_cfg_into` folds one configuration into the policy being built, and the base files and the
task configurations go through exactly the same call. That is what makes the model additive in
every dimension:

| Part | Merge rule |
| --- | --- |
| the eight filesystem path sets | union, through `fs_union_dir`, canonicalised and de-duplicated per right |
| `net.rules`, `bind.rules`, `accept.rules` | union of distinct lines, in the order first seen |
| the timeout and each resource limit | a zero disables and wins; otherwise the largest value |

The limit rule is the same within a file and across files, so the order the configurations are
read in does not matter.

## The three checks that live here

Each of these is asked once, where the specification is written, rather than in the layer that
would otherwise ask it. A layer may be absent from the chain, and a rule has to be judged
either way, or the specification carries something that is silently dropped.

| Check | What it refuses |
| --- | --- |
| `refuse_unenforceable_network_rules` | a port outside 1 to 65535, an external host with no port, a loopback wildcard beside a concrete port |
| `refuse_unenforceable_accept_rules` | a public port below 1024, a public port the command may bind, a backend port `[bind]` does not name, two rules fronting one public port |
| `refuse_spec_dir_under_write_path` | a specification directory beneath any write, create, delete, inter-process communication (IPC), symbolic-link or restructure path |

The last one is the one with teeth: the directory holds `net.rules`, which the connect guard
reads before Landlock is applied, and the process identifiers the clean-up kills. A command
able to write there could rewrite the connect policy or aim the kill anywhere. Both sides are
resolved through their symbolic links before they are compared.

## Two canonical forms

`phobos-paths.sh` offers both, and the difference is load-bearing:

- **`canon_paths`** canonicalises without resolving symbolic links, because the merge compares
  what the policy wrote.
- **`resolve_symlinks`** resolves them, because Landlock anchors a rule on the inode it opens,
  so `/bin` and `/usr/bin` are one tree on a merged-usr system.

Both need a GNU `realpath`. `refuse_missing_realpath` runs the tool rather than looking for its
name, because a `realpath` that refuses those options would otherwise pass and leave every path
to a fallback that compares spellings. Two names for one tree would then look like two trees,
and a narrowing rule beneath a wider one would go unnoticed: a weaker sandbox that still looks
like one.

## Known gaps

**`[accept]` sources are validated twice, loosely then strictly.** The parser checks only that
a source is made of the characters an address or a range uses; HAProxy validates it in full
when the filter starts. A malformed source therefore surfaces as a filter that fails to start
rather than as a policy error.

**The redundancy probe is not in continuous integration (CI).** `tests/policy-redundancy-probe.sh` reports which entries
grant Landlock nothing an ancestor already grants. Those entries are not dead code, so the
probe reports and never fails, which means a freshly pruned policy is only judged where
somebody runs it, rather than on every CI run.

## Further reading

- [Policy Reference](/user/policy-reference/) — the same format, for whoever writes one
- [Life of a sandboxed run](../life-of-a-sandboxed-run.md) — where this stage sits
- [Filesystem subsystem](filesystem.md) — the consumer of the path sets
