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
a second implementation: everything it starts is the script or the container it names. Its
commands live in the folder `phobos-cli/` beside it, one file each, in a checkout and in the image
alike. Without that folder it starts nothing and ends with status 15.

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

## The menu

```bash
./phobos-cli.sh
```

Called without a command while its input and output are a terminal, the script opens a menu. The
menu asks for the answers of one call and shows the call they make. It then runs `phobos-cli.sh`
with exactly that call and prints it at the end, quoted as bash reads it, so that you can repeat it
without the menu. The menu is a front end and nothing more: every check and every refusal of the
command line applies to what it runs. Without a terminal, a call with no command is still a usage
error, so a script or a pipeline never waits for an answer. `--dry-run` and `--mode` apply to the
menu as to a command.

The menu is drawn by `dialog`, which every run-phase image ships. On a host, install it first
(`brew install dialog` on macOS, `apt-get install dialog` on Debian or Ubuntu); without it the menu
ends with status 15 and says so. Choose with the arrow keys or the mouse and Enter; Esc goes back.

**Run a command under an existing policy** asks for a policy directory, a policy in it and the
command. On a host it first asks for the language and the exercise directory. On request it sets the
limits, the network, a resolver and the debug report. Look for policies among your own files, not in
the exercise. A submission can place a policy file there that grants it anything, so the menu uses a
policy inside the exercise only after a second confirmation. The command is split into words at
spaces. Quotes, variables and wildcards are not interpreted, so what you see is what runs.

**Write a new policy step by step** asks where to save the policy and which of the thirteen sections
to fill, then for the entries of each. Each section asks in the shape its grammar takes: a path, a
host and a port, a port, an exposed listener, or the limits in one form. The menu asks again for an
answer the grammar cannot hold, such as a relative path, a port out of range or a timeout without
exactly three decimals. The menu never saves the policy inside the exercise, and it replaces an
existing file only after a question. Before the command, the menu can run `/bin/true` under the new policy. That shows
whether the policy system accepts it and the layers start with it. A dry run saves nothing and prints
the policy instead.

**Record a reference program and derive a policy** runs the recording pruner, described under
[Recording](#recording). The program runs with no sandbox while the pruner records it, so the menu warns
first and goes on only on Yes: record your own reference program, never a submission. The menu asks
for the exercise, whether the program needs the network, a name for the recording and the command.
It then records one session or more, generates the policy and, on a host, offers a replay in a new
container that fails on every refusal of something the recording did. A failed step ends the menu
with its status, unless you keep its result. The menu saves the policy the same way as a written
one, and can run a command under it. Inside an image this works only in the prune image, which
mounts the helpers of the pruners, and the replay needs a host.

**Derive a policy from past student submissions** runs the command described under
[A policy from submissions](#a-policy-from-submissions), on a host only. The menu warns first and goes
on only on Yes. It asks for the template, the directory of the submissions and which of them to use,
your declaration about the assignment directory, where the run goes and whether to verify. It then
lists every row of the candidate policy, those the fewest submissions needed first, for you to
untick the rows you do not want the policy to grant. The menu always checks the rows you keep against the run
and saves them the same way as a written policy.

Inside an image the menu first copies the policy into a private directory under `/var/tmp` and has the
policy system check it there. The policy system checks a new policy the same way, beside its
destination. The policy system refuses a policy that lets the sandboxed command
change anything where that copy lies. The sandboxed command can therefore never change the policy it
runs under. Such a policy has to be run from a host, where the copy stays outside the container. A
dry run copies nothing.

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
| `--language <java\|python\|c-fact\|r\|swift\|c-gcc\|cpp>` | host | The run-phase image. The default is `java`. |
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
| `java-gradle`, `java-maven`, `python`, `c-fact`, `r`, `swift`, `c-gcc`, `cpp` | The Compose service `prune_java_gradle`, `prune_java_maven`, `prune_python`, `prune_c_fact`, `prune_r`, `prune_swift`, `prune_c_gcc` or `prune_cpp`. |
| `java-egress` | The service `prune_java_egress`, under the `egress` profile. |
| `all` | The seventeen jobs of the layer pruner in order: the eight prunes, the merge, and the eight verifications. It stops at the first job that fails and ends with that job's status. |

Every job is rebuilt first, so an image that already exists is never reused on a stale base. The
key decides the run-phase image. `python` uses the Python image, `c-fact` the C image, `r` the R image, `swift` the Swift image, `c-gcc` the GCC image, `cpp` the C++ image, the others the Java image. Inside
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
program and never for a submission. `--language <java|python|c-fact|r|swift|c-gcc|cpp>` chooses the image the recorder is
built on (the default is `java`), `--exercise <dir>` mounts the exercise read-only, and `--networked`
selects the service that has a network. The verbs are `record`, `generate`, `check` and `diff`.

## A policy from submissions

```bash
./phobos-cli.sh submissions --template ./tests --submissions ./past --output ./runs --assignment-is-student-code
./phobos-cli.sh submissions verify --run ./runs/submissions-run.ab12CD34 --policy ./edited.cfg
```

The command derives a policy for an exercise from past student submissions, on a host. Each child
directory of `--submissions` replaces the `assignment` directory of a copy of `--template`, the
exercise's test repository. The layer pruner then prunes each copy in a fresh container without
network, and the command merges the policies beside the grading bases of the run-phase image the
template's key names. Build that image first with `build`. The layers must start under the result
with every submission, and unless `--no-verify` every submission must match its own reference under
it. Everything goes to a new directory beneath `--output`: the staged copies, what the pruner wrote,
`union/candidate.cfg`, `union/report.json` with how many submissions needed each row, and
`policy.cfg` once the verification passes.

:::warning[Vetted submissions only]
The pruner runs each submission once without Phobos, so a submission can shape its own result, and
through it the merged policy. Use past submissions you have vetted and consider harmless, never
untrusted ones. A submission cannot change the template, another submission or anything on the host
outside its own output directory, and the command refuses a result changed after the pruner wrote it.
:::

`--assignment-is-student-code` is your declaration that the template's `assignment` directory holds
only student material, while the tests, the build script and `prune.json` lie outside it. The command
refuses a template that holds a link or a special file, a key it does not prune for, declared hosts,
and a report glob that could reach the `assignment` directory. A submission that is or holds a link
or a special file is left out, and the command says why. `--submission <name>` limits the run to the
submissions named.

`verify` checks an edited policy against a finished run again: the layers start under it and, unless
`--layers-only`, every pruned submission must match. It ends with 0 when all matched, 1 when a
submission did not, and 15 when a step failed for another reason, such as a changed input.

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
