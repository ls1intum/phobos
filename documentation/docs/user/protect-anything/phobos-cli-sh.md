---
title: "phobos-cli.sh"
sidebar_position: 6
description: "One command line for the sandbox and both pruners, on a host with Docker or inside an image."
---

:::tip[Simple Story]
The workshop has one front door.

Through it you can send a worker to the bench, ask the surveyors to map what a job needs, or order
a new bench. The door never opens onto a room where the bench lacks its walls. For that, you go
round the back, on purpose.
:::

`phobos-cli.sh` sits at the root of the repository. It starts `phobos.sh`, the layer pruner and
the recording pruner, and it builds the run-phase image. It is a convenience around those, never
a second implementation: everything it starts is the script or the container it names.

It is not the entry point for grading. A grader calls `phobos.sh`, which can switch a layer off for
diagnosis. `phobos-cli.sh` refuses those switches, so nothing started through it runs less confined
than the policy says.

## Two places, one command line

| Where | What it does |
| --- | --- |
| On a host | It starts Docker. The image carries the sandbox, so the command runs in a container with a network of `none`, a memory limit and a process limit. |
| Inside an image | It starts what the image holds, at `/var/tmp/opt/core`, and the pruners where you mount their helpers. |

One fact decides the place: whether the directory `/var/tmp/opt/core` exists. Nothing in the
environment can change that. `--mode host` or `--mode image` can confirm the place and never
overrides it, and an image whose `phobos.sh` is missing is a broken image, never a host.

`--dry-run` prints the commands instead of starting them, one block per command: a `COMMAND`
line, one argument per line, an `END` line.

The script needs bash 4.4 or newer. On macOS the system bash is 3.2, so the script starts
`/opt/homebrew/bin/bash` or `/usr/local/bin/bash` when it finds one there, and says what to
install when it does not.

## Running a command

```bash
./phobos-cli.sh run --language java --exercise ./my-exercise --config exercise.cfg -- ./gradlew test
```

On a host, Docker mounts the exercise directory read-write as `/var/tmp/testing-dir`, the working
directory of the sandboxed command. The script copies each configuration into a private directory
and mounts that read-only, so the sandboxed command cannot write one. A configuration can therefore
sit inside the exercise directory: the copy is what the run reads.

| Option | Where | What it is for |
| --- | --- | --- |
| `--config <file>`, `-c <file>` | both | An exercise configuration. Repeatable. |
| `--project-root <dir>` | both | The directory an Ares 2 policy resolves its relative paths against. On a host it is relative to `--exercise` and must stay inside it. |
| `--resolver <ip[:port]>` | both | The resolver the egress broker uses for an exact host name. |
| `--debug`, `-d` | both | Report what each layer does, on stderr. |
| `--language <java\|python>` | host | The run-phase image. The default is `java`. |
| `--image <name>` | host | A run-phase image by name. Not together with `--language`. |
| `--exercise <dir>` | host | Required. |
| `--network <name>` | host | A Docker network, `none` by default. The script refuses the network of the host and the network of another container. |
| `--memory <size>` | host | The default is `8g`. |
| `--pids-limit <n>` | host | The default is `1024`. |
| `--cpus <n>` | host | No default. |

Everything after `--`, or after the first word that is not an option, is the command, with its own
options. The command line inserts exactly one `--` before it, because `phobos.sh` treats
everything after its first `--` as the command.

### What it refuses

In both places, with status 2 and before anything starts:

- every switch that turns a layer off: `--no-restriction`, `--no-filesystem-restriction`,
  `--no-networksystem-restriction`, `--no-timeoutsystem-restriction`,
  `--no-resourcesystem-restriction` and their short forms;
- every `--*-bin` option, which replaces an enforcer;
- any option this page does not list.

Call `phobos.sh` directly inside the image to debug with a layer off. The Docker command the script
builds never carries `--privileged`, `--cap-add`, `--security-opt`, a device, a namespace of the host or
the Docker socket, and no option or option value can add them.

## Pruning

```bash
./phobos-cli.sh prune python
./phobos-cli.sh prune all
```

| Key | What runs on a host |
| --- | --- |
| `java-gradle`, `java-maven`, `python` | The Compose service `prune_java_gradle`, `prune_java_maven` or `prune_python`. |
| `java-egress` | The service `prune_java_egress`, under the `egress` profile. |
| `all` | The seven jobs of the layer pruner in order: the three prunes, the merge, and the three verifications. It stops at the first job that fails and ends with that job's status. |

Every job is rebuilt first, so an image that already exists is never reused on a stale base. The
key decides the run-phase image: `python` uses the Python image, the others the Java image. Inside
an image, `prune` starts `/var/tmp/helpers/exercise_pruner/src/interface/main.py` when you mount the helpers there.
There, `java-egress` needs `--resolver <ip[:port]>`, and `all` needs a host because the merge is a
separate image.

On a host the command line anchors Docker Compose to the checkout it sits in. A compose file or a
`.env` file in the working directory, and the variables `COMPOSE_FILE`, `COMPOSE_PROJECT_NAME` and
`COMPOSE_PROFILES`, change nothing.

## Recording

```bash
./phobos-cli.sh record --exercise ./reference record --name tool --script session.script -- python3 -q
./phobos-cli.sh record generate --name tool
```

The recording pruner runs the program with no sandbox at all, for the instructor's own reference
program and never for a submission. `--language <java|python>` chooses the image the recorder is
built on (the default is `java`), `--exercise <dir>` mounts the exercise read-only, and `--networked`
selects the service that has a network. The verbs are `record`, `generate`, `check` and `diff`.

## Building the image

```bash
./phobos-cli.sh build java
```

`build` assembles `build/run-phase-context` with `.github/scripts/assemble-run-phase-context.sh`
and then builds the image of the language. It works on a fresh checkout and needs no image. It
needs a host with Docker.

## Exit statuses

| Status | Meaning |
| --- | --- |
| The command's own | The command ran. |
| 2 | The call was made the wrong way. |
| 15 | The command could not start: no Docker, a missing component, or a leaked `BASH_ENV`, `ENV`, `LD_PRELOAD`, `LD_LIBRARY_PATH` or `LD_AUDIT`. |

Bash and the loader read `BASH_ENV` and the `LD_*` variables before the first line of a script, so
the script can only refuse to run when it finds one set. Start it without them. It cleans `PATH`,
`CDPATH`, `TMPDIR` and the other lookup variables like every other entry point of Phobos.
