---
title: "Policy Cookbook"
sidebar_position: 0
description: "Six situations, each with the smallest policy that solves it and the wrong version that looks like it does."
---

:::tip[Simple Story]
The reference tells you what each section means. This tells you what to write.

Every recipe has the same four parts: the situation, the fragment that solves it, what it still
forbids, and the version that looks right and is not.
:::

Each recipe is a fragment. Paste it into a task configuration, which is applied on top of the
base policy for the runtime environment, and name that file with `--config`.

```bash
${PHOBOS_HOME}/phobos.sh --config exercise.cfg -- <your command>
```

| Recipe | The situation |
| --- | --- |
| [Reading a data tree](reading-a-data-tree.md) | the command reads a directory of input and changes nothing |
| [Running a program tree](running-a-program-tree.md) | the command runs a tool that is not in the base policy |
| [Writing an output file](writing-an-output-file.md) | the command produces one file in one place |
| [Allowing exactly one host](allowing-exactly-one-host.md) | the command fetches from one host and no other |
| [Exposing a listener](exposing-a-listener.md) | the command serves something that has to be reachable |
| [Setting time and memory budgets](setting-time-and-memory-budgets.md) | the run has to end, whatever the command does |

Two habits are worth carrying through all six.

**Check both directions.** A test that shows the permitted case working proves nothing about
containment, and a test that shows the forbidden case refused proves nothing about usability.
Run the command with the fragment and confirm that it succeeds, then take one line out and
confirm that it fails.

**Read the effective policy before you trust it.** `--debug` prints the whole policy each layer
was given, including the rights that hold after the union. A fragment that reads
narrower than it is shows up there.
