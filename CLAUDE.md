# CLAUDE.md

@AGENTS.md

That import is this file's content. `AGENTS.md` holds the conventions this repository is
held to, written for whoever is doing the work, and a rule restated here would be a second
copy free to drift from the first. What this file adds below the reminders is orientation
rather than convention: what the project is, how it is built, and where its parts live.

What follows are deliberately abbreviated reminders of the four conventions an agent gets
wrong most often. All four are stated in full above, and where the short form and the full
one disagree, the full one is right.

- Run `gh pr list` before branching. Work here is stacked: a pull request whose base is
  another branch rather than `main` is part of a stack, and a change written against `main`
  alone can be correct and still conflict with it.
- Never add a bind, a capability or an allowed host to make a test pass. That turns a
  containment failure into a widened boundary, and the suite goes green either way.
- `*.cfg` and `*.paths` are read with `while IFS= read -r`, so a carriage return ends up
  inside a path and the run silently loses access the policy granted. Every text file is stored with LF, and
  `.gitattributes` keeps it that way.
- `gh pr create --body` bypasses `.github/PULL_REQUEST_TEMPLATE.md` silently, so read that
  file before writing a body, and check it with
  `PR_BODY="$(cat body.md)" java .github/scripts/CheckPullRequestTemplate.java`.

## Project Overview

Phobos runs a student submission for an Artemis programming exercise with access to only
what the exercise's own tests were shown to need. It works in two phases.

**Resource discovery, offline.** The layer pruner runs the reference exercise through the
grading layers, starting from a policy that grants nothing, grants exactly what each refusal
it records proves, removes what turns out unneeded, derives the limits, and writes a complete
configuration per exercise. The orchestrator merges them into one base per language and a
small file per exercise.

**Sandbox application, at grading time.** The submission runs under a Landlock ruleset that
grants exactly the rights the policy names on those paths; every other path is denied, though
it stays visible by name. Outbound connections are supervised by the connect guard, which
enforces the `[connect]` allow-list by host and port from outside the process; a `[connect]`
rule that names a host is enforced by the egress broker (an HAProxy that checks the TLS host
name), which the network layer starts automatically for such a rule; an exact-name rule is
refused when no resolver is given. A timeout and resource limits bound the run, and the
container around it supplies `--network none` and the cgroup caps. A supervisor, the connect
guard when the network layer is on and a report-only one when it is off, prints a
`Phobos Security Error` line on stderr for each distinct action it can attribute with
certainty to Landlock, the guard or the timeout's group lock, staying silent wherever it is
in doubt. It never lets a refused call succeed nor a permitted one fail.

The point of the split is that the expensive, fragile part happens once per language
environment, offline, and grading itself only applies a fixed configuration.

## Tech Stack

- POSIX shell for the wrapper and the layers, which is the bulk of the repository
- C for `phobos-landlock-filesystem-and-networksystem`, the connect guard, the timeout's group lock and the report-only supervisor `phobos-seccomp-filesystem`, all four compiled inside the run-phase image
- Python for the prune orchestrator and the artefact helpers
- Docker for both phases, one image per language environment
- Java for the two template checkers in `.github/scripts/` and for the two acceptance fixtures
- Docusaurus, Node 24 and pnpm for the documentation site under `documentation/`, tested with Playwright

The filesystem layer is enforced by Landlock, an unprivileged Linux kernel sandbox, applied
by `phobos-landlock-filesystem-and-networksystem` (the C program under `protecter/src/`). The run phase needs no privileges, no
capabilities and no container flags. The prune runs the layer pruner
(`pruner/exercise_pruner/`, in the image of `docker/pruner/layers/`), which measures under the
grading layers themselves, observing their refusals with `strace`; README.md, "The layer
pruner", says how to run it. Nothing uses Bubblewrap any more.

## Build and development commands

There is no build system. The shell runs as it is, and the C is compiled inside the image.

Both of these run **inside the run-phase image**, where `PHOBOS_HOME` is `/var/tmp/opt/core`. The
shipped base policy is the `Base*.cfg` the image put beside `phobos-policysystem.sh`, so it is applied
without being named; `--config` is for an exercise configuration on top of it. A bare checkout keeps
those files in `protecter/src/config/` rather than beside `phobos-policysystem.sh`, so a run from one is refused
with `PHB-EPOLICY` rather than run unconfined.

```
# Apply the sandbox to a command
${PHOBOS_HOME}/phobos.sh --config <exercise.cfg> -- ./gradlew test

# Every script prints its own manual, naming each flag it takes
${PHOBOS_HOME}/phobos.sh --help

# Layer switches, for isolating which layer a failure belongs to
${PHOBOS_HOME}/phobos.sh --no-timeoutsystem-restriction --config <exercise.cfg> -- <command>

# A single layer on its own, which builds its own specification from a config through
# phobos-policysystem.sh and enforces only that layer's concern
${PHOBOS_HOME}/phobos-networksystem.sh --config <exercise.cfg> -- <command>
```

A run given no `--config` is not a grading run. Phobos then takes its most restrictive shape
and drops every `[connect]`, `[bind]` and `[accept]` rule the base granted, loopback
included, so a Gradle build cannot reach its own daemon. The filesystem keeps what the base
granted, because a command whose binary and libraries were denied could not start at all.

Every entry point starts by removing each `PATH` entry that is not absolute, unsetting `CDPATH`
and dropping what is not absolute from `TMPDIR`, `GCONV_PATH`, `LOCPATH`, `NLSPATH`,
`HOSTALIASES` and `TZDIR`, before it runs any program, because the current directory may be the
submission's tree. The command sees the cleaned environment, so it is named by its path
(`./gradlew`), and a `PATH` with no absolute entry is refused with `PHB-ERUNTIME`. Every script
under `protecter/src/` begins with `#!/bin/bash`, so bash itself is never looked up through `PATH`
(AGENTS.md states the rule). What no script can clean, `BASH_ENV` and the loader's `LD_*`, is an
integration requirement in SECURITY.md.

### The command line

```
# On a host: build the image, run a command in an ordinary container with limits, prune and record
./phobos-cli.sh build java
./phobos-cli.sh run --exercise ./my-exercise --config exercise.cfg -- ./gradlew test
./phobos-cli.sh prune python        # one Compose service, rebuilt first; "prune all" runs the seven jobs in order
./phobos-cli.sh record generate --name tool
./phobos-cli.sh --dry-run run --exercise ./my-exercise -- true    # print the commands, start nothing
```

Inside an image the same `run`, `prune` and `record` start `phobos.sh` and the helpers of the pruners
directly. `run` refuses every `--no-*` switch and every `--*-bin` override in both places; to debug with a
layer off, call `phobos.sh` directly.

### The linters, which are the gate

`lint.yml` runs seven lint jobs, and `actionlint.yml` lints the workflows beside it, weekly
as well as on a change under `.github`. Neither is the whole of CI: `test.yml` runs the shell and
Python suites, `build.yml` builds the images for amd64 and arm64, runs the two C unit suites
and holds the run-phase image to the Landlock acceptance suites and the protection matrix inside
it, `codeql.yml` scans, `pullrequest-template.yml` checks the body, and `documentation-ci.yml`
holds the documentation site to its own gate (see `documentation/README.md`). The lint jobs are the ones you can run in full by hand before opening a pull request.

```
# Same file sets and same flags as CI. Together these are the seven lint.yml jobs plus
# actionlint, and the C job is two
# steps rather than one: the compiler gate runs before cppcheck and fails on any warning.
find . -name '*.sh'  -type f -print0 | xargs -0 shellcheck -x -S warning
( failed=0; while IFS= read -r f; do gcc-14 -std=gnu23 -fsyntax-only -Wall -Wextra -Werror -fanalyzer "$f" || failed=1; done < <(find . -name '*.c' -type f); exit "$failed" )
find . -name '*.c'   -type f -print0 | xargs -0 cppcheck --std=c23 --enable=warning --quiet --error-exitcode=1
ruff check --no-cache .
bandit --recursive --ini .bandit --severity-level medium pruner/exercise_pruner/src pruner/runtime_pruner/src pruner/shared/src
yamllint --strict .
find . -name 'Dockerfile*' -type f -exec sh -c 'hadolint --config .hadolint.yaml < "$1"' _ {} \;
actionlint
ec --no-color                      # editorconfig-checker, configured by .editorconfig-checker.json
awk 'FNR==1{p=""} /^[a-zA-Z_][a-zA-Z0-9_]*\(\)/{if(p !~ /^[[:space:]]*#/){print FILENAME":"FNR; e=1}} {p=$0} END{exit e}' protecter/src/*.sh protecter/src/phobos-tools-*/*.sh
```

One of those is narrower than it looks: `bandit` runs over exactly two directories, not the
whole tree, because everything else Python here is fixture. `hadolint` matches `Dockerfile*` at
any depth, which reaches every one under `docker/`. CI runs
shellcheck and hadolint inside pinned container images, installs cppcheck with apt, and
downloads `actionlint` and `editorconfig-checker` at a pinned version and checksum; the commands above assume the tools are installed locally and will
differ in version, which is the usual reason a local run and CI disagree.

`.bandit`, `.yamllint` and `.hadolint.yaml` at the repository root carry the thresholds and
the exceptions. A finding is fixed rather than suppressed unless the suppression carries a
comment saying why.

### The images

```
docker compose -f docker-compose.yaml up --build        # the prune environments
.github/scripts/assemble-run-phase-context.sh build/run-phase-context   # the build context the compose file reads
docker compose -f docker/protecter/java/docker-compose.yaml up --build
docker build -f docker/protecter/java/Dockerfile -t phobos-run-phase:ci build/run-phase-context
# an acceptance suite, in an ordinary container: no --privileged, no --cap-add, no --security-opt
docker run --rm --network none -v "$PWD/protecter/test:/tests:ro" phobos-run-phase:ci \
  bash /tests/integration/landlock-filesystem-and-networksystem-acceptance/run-tests.sh
docker compose -f docker/protecter/python/docker-compose.yaml up --build
```

Each prune container works independently on its language and writes its result into the
shared `build/pruner/path_sets` directory; nothing passes between containers except through
`build/pruner`. Each language's prune needs its run-phase image (`phobos-run-phase-java`,
`phobos-run-phase-python`) built first, and `verify_java_gradle` and `verify_python` re-run the
exercises under the merged configuration at the end.

### The host

The run phase installs nothing on the host and changes no host state. Landlock, the connect
guard and the timeout are all self-imposed by the unprivileged process, so there is no
profile to deploy and no root step. The one thing the grading container must add from
outside is `--network none` and cgroup limits, which Phobos cannot set for itself.

## Project structure

```
protecter/                 the sandbox and the tests that hold it
  src/                     the sandbox itself, the part that is shipped in the run-phase image
    phobos.sh                entry point: parses the configuration, applies the layers
    phobos-policysystem.sh   turns the base and exercise configuration into a run's specification
    phobos-filesystem.sh     the filesystem layer, reads the path sets and applies Landlock
    phobos-networksystem.sh  the network layer, runs the connect guard and the egress/inbound HAProxy
    phobos-timeoutsystem.sh  the timeout layer, which applies the group lock when a timeout is set
    phobos-resourcesystem.sh the resource layer, sets the rlimits the policy names, started by the filesystem layer right before Landlock
    phobos-landlock-filesystem-and-networksystem/  its *.c/.h: the C program that applies the Landlock policy, then exec's
    phobos-seccomp-networksystem/  its *.c/.h: the connect guard, supervises connect() and enforces [connect] by host and port; with the network layer on it is also the run's one reporting supervisor
    phobos-seccomp-timeoutsystem/  its *.c: the group lock, a seccomp filter refusing setsid and setpgid, then exec's
    phobos-seccomp-filesystem/     its *.c/.h: the denial reporter (wording, counts, the mirror of Landlock) and, as its main, the report-only supervisor that runs when the network layer is off; the connect guard links the rest
    phobos-tools-common/     sourced by every layer through phobos-common.sh, which sources the rest here but phobos-environment.sh, and the per-subsystem helpers
      phobos-environment.sh  sourced first by every entry point: PATH and the other lookup variables made safe before anything is looked up
      phobos-common.sh       the shared entry the layers source; it sources the others
      phobos-constants.sh    the numbers the scripts share, named once, the exit statuses among them
      phobos-log.sh          reporting, and wording the resource limit that ended a run
      phobos-paths.sh        the two canonical forms a path is compared in
      phobos-time.sh         the timeout contract: how a value is spelled and compared
      phobos-spec-dir.sh     the specification directory and its lifetime
      phobos-signals.sh      passing a caller's signal on to the command a layer waits for
    phobos-tools-policysystem/
      phobos-policy-parse.sh one cfg in, the parsed state and the specification files out
      phobos-policy-yaml.sh  a strict subset of YAML in, flat records with line numbers out
      phobos-language-configuration.sh  a programming language configuration in, its bases, placeholder values and [connect] rows out
      phobos-policy-ares.sh  an Ares 2 security policy in, the same parsed state a cfg gives out
    phobos-tools-filesystem/
      phobos-rights.sh       a parsed policy to the --rights= arguments phobos-landlock-filesystem-and-networksystem takes
    phobos-tools-networksystem/
      phobos-haproxy.sh      the egress broker and inbound filter: turns [connect]/[accept] into an haproxy.cfg
      phobos-network-args.sh [connect] and [bind] to the TCP and UDP port rules Landlock enforces
    config/                  BaseLanguage-<lang>.cfg and TailPhobos.cfg, the shipped policy
      language-configurations/  one file per Ares 2 programming language configuration: its bases, placeholders and [connect] rows
  image/                   what the run-phase image build pins: pin-repository.sh and the Maven and Gradle repository manifests
  test/                    unit/ (C and shell units), integration/ (shell suites, the acceptance suites and
                           protection-matrix/), harness.sh, harness_self_test.sh and a policy probe
pruner/                    the pruners, which discover what a policy needs
  exercise_pruner/         the layer pruner and the orchestrator: prune a reference exercise through the grading layers
                           (observe, attribute, grow, minimise, limits, verify, write) and merge the results
  runtime_pruner/          the recording pruner: record a session unsandboxed, generate a policy, replay it, compare
                           it (prune image only)
  shared/                  what both need: the policy model, the strace parser, attribution, generalisation, limits
                           and the sampler. Each of the three has src/ and test/ (unit/, integration/), and inside
                           those the layers domain/, infrastructure/, application/ and interface/ where it has code;
                           pruner/README.md says which layer may import which
  src/orchestrate/         the orchestrator: merges the pruned exercise policies into the shipped bases
  config/                  what the prune image carries: BasePrune.cfg, which grants nothing, and the language seeds
  test/                    integration/ (the pruner suites and their fixtures), python/, and the runner probes
docker/pruner/             the layer pruner's image and the orchestrator's
  layers/                  the layer pruner's image: the run-phase image, strace, the probe, an empty base
  orchestrate/             the orchestrator's image
docker/protecter/          the images an exercise actually runs in, one per language (java/, python/)
exercises/                 the reference exercises: the pruners' input and the protecter's acceptance fixtures
phobos-cli.sh              one command line for phobos.sh, the layer pruner, the recording pruner and the image build; on a host it
                           starts Docker, in an image it starts what the image holds, and it refuses every switch that turns a layer off
documentation/             the Docusaurus site, with its own gate
build/                     generated and ignored: the assembled image context, and pruner/ with path sets, recordings and the merged config
```

## Coding conventions

- One variable or function declaration per line, in every language.
- British English in all prose, comments and messages.
- Every function in the shell scripts of the protecter (`protecter/src/*.sh` and `protecter/src/phobos-tools-*/*.sh`) says what it does and what it assumes about its environment.
  AGENTS.md states this in full.
- Shell is POSIX where it can be and bash where it must be; say which at the top of a file.
- A `shellcheck` directive carries a comment on the line above saying why the finding is
  acceptable here.
