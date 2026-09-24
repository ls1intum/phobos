---
title: "Running a program tree"
sidebar_position: 2
description: "Permitting a tool outside the base policy to be executed, with the read right it needs to load."
---

:::tip[Simple Story]
A tool has to be taken out of its drawer and switched on. Those are two permissions, and a
policy that grants only the second fails on the first.
:::

## The situation

The command runs a tool that the base policy for this runtime environment does not name: a
linter, a compiler or a helper installed into its own prefix.

## The policy fragment

```ini title="exercise.cfg"
[read]
/opt/toolchain

[execute]
/opt/toolchain
```

Both sections name the same tree. The rule that results carries `rx`, one entry, one target.

## What this still forbids

- writing anywhere in the tool's tree, so the command cannot replace the tool it runs
- creating or deleting anything in it
- every path the tool itself might reach that the base policy does not name, its configuration
  and its caches among them

## The tempting wrong version

```ini title="wrong.cfg"
[execute]
/opt/toolchain
```

Execute alone fails at the first open. The loader reads the program image and the shared
objects beside it, and reading is a separate right. The failure looks like a missing file
rather than a missing permission, which is why this one costs time.

The second tempting version grants more than it means to:

```ini title="also-wrong.cfg"
[read]
/opt

[execute]
/opt
```

Naming the parent because the exact prefix is inconvenient hands the command every other tool
under `/opt` as well. Name the prefix the tool lives in.

## Notes

- An interpreted tool splits the other way: `[execute]` on the interpreter, `[read]` on the
  script.
- A tool that needs a cache directory needs a writable path too. That is
  [Writing an output file](writing-an-output-file.md), or
  [`[restructure]`](/user/policy-reference/restructure) where it renames files into place.
- A tool that reaches the network needs [`[connect]`](/user/policy-reference/connect), and it
  will otherwise fail with a resolver error rather than a permission error.
