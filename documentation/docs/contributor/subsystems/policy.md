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

`phobos-policysystem.sh` discovers the base policy, parses every configuration, merges them and
writes one file per part into a directory the caller owns. It is the only parser: a layer
running on its own over `--config` calls this program too, so no layer ever reads a
configuration file itself.

```
phobos-policysystem.sh [--debug] --spec-dir <dir> [--tail-flags-file <file>] [--config <file>]...
```

The caller creates and owns the directory and removes it when the run ends. This program only
writes into it, using a scratch subdirectory of it for its own temporary files, so everything
it makes is removed with the directory rather than left in `/tmp`, which the policy itself
usually makes writable.

## What is in it

| File | What it holds |
| --- | --- |
| `phobos-policysystem.sh` | the program: base discovery, the merge, the checks, the write |
| `phobos-policy-parse.sh` | one configuration in, the parsed state and the per-right files out |
| `phobos-language-configuration.sh` | a programming language configuration in; the base policies it names, its `[connect]` rows and the value of each placeholder on first use out. Sourced, and used whenever a run imports an Ares 2 policy |
| `phobos-policy-yaml.sh` | a strict subset of YAML in, flat records with line numbers out; sourced, and used by `phobos-policy-ares.sh` |
| `phobos-policy-ares.sh` | an Ares 2 security policy in, the same parsed state a configuration gives out |
| `phobos-rights.sh` | a parsed policy to the `--rights=` arguments `phobos-landlock-filesystem-and-networksystem` takes |
| `phobos-network-args.sh` | `[connect]` and `[bind]` to the Landlock port rules, and the refusals |
| `phobos-spec-dir.sh` | the specification directory, its marker, and its lifetime |
| `phobos-paths.sh` | the two canonical forms a path is compared in |
| `phobos-time.sh` | how a timeout is spelled, merged and compared |
| `phobos-constants.sh` | the exit statuses and the other shared numbers |
| `phobos-log.sh` | reporting, and the line for a resource limit the command hit |
| `phobos-signals.sh` | passing a caller's signals on to the command a layer waits for |
| `phobos-environment.sh` | the startup environment made safe: `PATH` and the other lookup variables keep only what is absolute, sourced by each entry point itself before anything else |
| `phobos-common.sh` | the aggregate every caller sources, which sources every file above but `phobos-policysystem.sh` and `phobos-environment.sh` |

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

## What the parser refuses, and where it says so

`parse_cfg_policy` reads a file line by line, and most refusals about one line go through
`refuse_cfg`, which says what is wrong and ends the message with `Found in <file>, line <n>`.
`refuse_unusable_port` and `refuse_wildcard_host_name` report directly, and add the same
location while the parser is reading.
It quotes the value with `${value@Q}`, so a control character or a byte that is not text
reaches the terminal as an escape. Some refusals name no line: a byte order mark, a NUL byte,
an unusable file, and a port checked in `phobos-network-args.sh` outside the parse loop.
Before the first line, `refuse_binary_cfg` looks for a byte order mark and a NUL byte. Each
line then faces one refusal everywhere, a carriage return. A line in a filesystem section faces
two more, a path that does not start with `/` and a path with `*`, `?` or `[`. A task
configuration adds a `[read]` or `[execute]` path that does not exist.
`phobos-policysystem.sh` asks `refuse_unusable_cfg_file` first, so a directory, a
link to nothing or an unreadable file is said to be that. A refusal ends the run before the
specification gets written, and the parser's scratch files exist by then.

`[connect]` lines are judged in `append_connect_rule` and `refuse_malformed_address`. A host
written like an address must be a valid one: IPv4 is four numbers from 0 to 255 without a leading
zero, and IPv6 has at most one `::` and no zone. A prefix runs from 1 to the address width, an
IPv4-mapped range needs at least 96 bits, and a colon needs a port after it. Anything else is
refused, because otherwise the connect guard reads it as a host name and opens its port to
every address. `is_ipv4_literal`, `is_ipv6_literal` and `count_ipv6_groups` are the predicates,
and the guard drops a rule written like an address that it cannot read
(`is_unreadable_address`). Further refusals sit in small functions. `append_connect_rule`
refuses an unknown transport and trailing words, `append_bind_rule` a target that is not a port,
and `append_accept_rule` a malformed `expose` line. `refuse_unknown_section` refuses an unknown
section, `read_limits_line` an unknown key, and `set_parsed_limit` a value with a space inside.

Every digit class is POSIX (`[[:digit:]]`, `[[:xdigit:]]`) or an explicit list. In a UTF-8
locale `[0-9]` matched Arabic-Indic digits, and an address written in them passed as an address
that the connect guard then read as a name. The parser further bounds a number by its digits
before any arithmetic, because bash arithmetic wraps without a word. `PHB_LARGEST_LIMIT_DIGITS`
is 18 and `PHB_LARGEST_TIMEOUT_SECOND_DIGITS` is 15.

## The YAML subset

`read_yaml_subset` in `phobos-policy-yaml.sh` reads one document of block mappings, block
sequences, the empty flow collections and one-line scalars, in UTF-8 with line feeds and no tabs.
It writes one record per node, `<line>\t<path>\t<type>\t<value>`, in document order. Anything
two YAML readers could read differently ends the run with `PHB-EPOLICY`, the file and the line.
Among those are an anchor, an alias, a tag, a block scalar, a second document, a duplicate key,
and a boolean or number a reader could take for a string. The reader can therefore be wrong only by refusing.
`phobos-policy-ares.sh` reads an Ares 2 policy through it, and
`tests/unit/phobos-tools-policysystem/yaml_subset.sh` holds it to both directions.

## Programming language configurations

A programming language configuration is data: one file per Ares 2 configuration name, such as
`JAVA_USING_GRADLE_ARCHUNIT_AND_ASPECTJ.cfg`, in `core/config/language-configurations/`. The
run-phase image copies that folder beside `phobos-policysystem.sh`, where the `Base*.cfg` glob
does not reach it. A file holds two sections. `[base]` names the base policies a run under that
configuration folds, and `[placeholders]` says how each placeholder of the language gets its
value: `environment`, `command-ancestor`, `fixed` or `password-database home`.
`phobos-language-configuration.sh` reads it, knows no language itself, and determines a
placeholder only when it is first used, so a source a run never needs cannot refuse it.
`tests/unit/phobos-tools-policysystem/no_language_in_code.sh` holds the code under `core/` to
naming no language. A run loads one when it imports an Ares 2 policy, and a run with `.cfg` files
only never does. A configuration can hold a `[connect]` section that accepts loopback rules
without a port and nothing else. The shipped Gradle and Maven configurations add `allow localhost udp`.

## The Ares 2 import

`phobos-policysystem.sh` picks the reader of a `--config` file by its name. `.yaml` and `.yml`
go to `phobos-policy-ares.sh`, every other file goes to `phobos-policy-parse.sh`, and each
reader refuses the other's format.

The importer reads the document through `read_yaml_subset` and checks it against version 1 of the
schema (`ares_check_schema`). It selects the programming language configuration that the policy
names (`ares_select_language_configuration`) and refuses a name with no file. It then maps the
policy to the parsed state a configuration gives. [The Ares 2 policy file](/user/ares-2-policy)
describes the mapping, the refusals and the summary line for users.

Three properties are worth knowing from the inside:

- `determine_language_placeholder` determines a placeholder only when a path uses it.
- The project root comes from `--project-root`, otherwise from the last `--chdir` of the tail
  flags. The importer refuses a root that is not the real path of a project directory.
- The importer refuses a path that reaches the project root through a symbolic link and so
  resolves elsewhere than it reads, because the submission's checkout can put a link there. It
  writes no row that the base already grants.

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
read in does not matter. A limit no configuration names takes a built-in default. The default is a
fallback and never a cap: a configuration naming a larger or a smaller value gets exactly that
value, and `0` switches the limit off. The defaults are 600 seconds, `mem_mb` 8192, `cpu` 600,
`nofile` 1024, `nproc` 256 and `fsize_mb` 256, in `phobos-constants.sh`. A run given no
`--config` drops every `[connect]`, `[bind]` and `[accept]` rule the base granted, loopback
included, and keeps the base's filesystem grants.

## The three checks that live here

Each of these is asked once, where the specification is written, rather than in the layer that
would otherwise ask it. A layer may be absent from the chain, and a rule has to be judged
either way, or the specification carries something that is silently dropped.

| Check | What it refuses |
| --- | --- |
| `refuse_unenforceable_network_rules` | a wildcard host name, a port outside 1 to 65535, an external host with no port. A loopback wildcard beside a concrete port is accepted: the guard alone enforces the port, and `emit_connect_port_args` logs which ports |
| `refuse_unenforceable_accept_rules` | a public port below 1024, a public port the command may bind, a backend port `[bind]` does not name, two rules fronting one public port with different backends |
| `refuse_spec_dir_under_write_path` | a specification directory beneath any write, create, delete, inter-process communication (IPC), symbolic-link or restructure path |

The last one is the one with teeth: the directory holds `net.rules` and `net.guard.rules`, which
the connect guard reads before Landlock is applied, and `hosts.record`, which names the hosts
file whose lines the clean-up rewrites. A command able to write there could rewrite the connect
policy or aim that rewrite at another file. Both sides are
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

- [Policy Reference](/user/policy-reference/): the same format, for whoever writes one
- [Life of a sandboxed run](../life-of-a-sandboxed-run.md): where this stage sits
- [Filesystem subsystem](filesystem.md): the consumer of the path sets
