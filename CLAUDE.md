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

**Resource discovery, offline.** Run the reference exercise repeatedly, hiding a directory
each time by overlaying it with an empty tmpfs, and observe whether the tests still pass. A
directory whose absence changes nothing was never needed and stays hidden; one whose absence
breaks the run is restored, read-only first and writable only if that is not enough. The walk
is top-down, so an unused subtree is dropped in one step rather than file by file. The result
is a path set: every path the run needs, with the access mode it needs.

**Sandbox application, at grading time.** The submission runs under a Landlock ruleset that
grants exactly the rights the policy names on those paths; every other path is denied, though
it stays visible by name. Outbound connections are supervised by the connect guard, which
enforces the `[connect]` allow-list by host and port from outside the process; a `[connect]`
rule that names a host is enforced by the egress broker (an HAProxy that checks the TLS host
name), which the network layer starts automatically for such a rule; an exact-name rule is
refused when no resolver is given. A timeout and resource limits bound the run, and the
container around it supplies `--network none` and the cgroup caps.

The two phases do not deny in the same way. While pruning, a hidden directory is an empty,
writable tmpfs; while grading, a path the policy does not name is refused with EACCES. A tool
that only needs some writable scratch directory can therefore pass the prune with that
directory hidden and still be refused at grading time, which is worth checking when a pruned
policy fails a run that passed its prune.

The point of the split is that the expensive, fragile part happens once per language
environment, offline, and grading itself only applies a fixed configuration.

## Tech Stack

- POSIX shell for the wrapper and the layers, which is the bulk of the repository
- C for `phobos-landlock-filesystem-and-networksystem`, the connect guard and the timeout's group lock, all compiled inside the run-phase image
- Python for the prune orchestrator and the artefact helpers
- Docker for both phases, one image per language environment
- Java for exactly one file, `.github/scripts/CheckPullRequestTemplate.java`

The filesystem layer is enforced by Landlock, an unprivileged Linux kernel sandbox, applied
by `phobos-landlock-filesystem-and-networksystem` (the C program under `core/`). The run phase needs no privileges, no
capabilities and no container flags. The discovery phase still uses Bubblewrap to hide
directories while it measures; the sandbox an exercise runs in does not.

## Build and development commands

There is no build system. The shell runs as it is, and the C is compiled inside the image.

Both of these run **inside the run-phase image**, where `PHOBOS_HOME` is `/var/tmp/opt/core`. The
shipped base policy is the `Base*.cfg` the image put beside `phobos-policysystem.sh`, so it is applied
without being named; `--config` is for an exercise configuration on top of it. A bare checkout keeps
those files in `core/config/` rather than beside `phobos-policysystem.sh`, so a run from one is refused
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

### The linters, which are the gate

`lint.yml` runs seven lint jobs, and `actionlint.yml` lints the workflows beside it, weekly
as well as on a change under `.github`. Neither is the whole of CI: `test.yml` runs the shell and
Python suites, `build.yml` builds the images and holds the run-phase image to the Landlock
acceptance suites inside it, `codeql.yml` scans, and `pullrequest-template.yml` checks the
body. The lint jobs are the ones you can run in full by hand before opening a pull request.

```
# Same file sets and same flags as CI. Together these are the seven lint.yml jobs plus
# actionlint, and the C job is two
# steps rather than one: the compiler gate runs before cppcheck and fails on any warning.
find . -name '*.sh'  -type f -print0 | xargs -0 shellcheck -x -S warning
( failed=0; while IFS= read -r f; do gcc-14 -std=gnu23 -fsyntax-only -Wall -Wextra -Werror -fanalyzer "$f" || failed=1; done < <(find . -name '*.c' -type f); exit "$failed" )
find . -name '*.c'   -type f -print0 | xargs -0 cppcheck --std=c23 --enable=warning --quiet --error-exitcode=1
ruff check --no-cache .
bandit --recursive --ini .bandit --severity-level medium docker/prune_phase/orchestrate var/tmp/helpers
yamllint --strict .
find . -name 'Dockerfile*' -type f -exec sh -c 'hadolint --config .hadolint.yaml < "$1"' _ {} \;
actionlint
ec --no-color                      # editorconfig-checker, configured by .editorconfig-checker.json
awk 'FNR==1{p=""} /^[a-zA-Z_][a-zA-Z0-9_]*\(\)/{if(p !~ /^[[:space:]]*#/){print FILENAME":"FNR; e=1}} {p=$0} END{exit e}' core/*.sh core/phobos-tools-*/*.sh
```

One of those is narrower than it looks: `bandit` runs over exactly two directories, not the
whole tree, because everything else Python here is fixture. `hadolint` matches `Dockerfile*` at
any depth, which reaches the four under `docker/`. CI runs
shellcheck, cppcheck and hadolint inside pinned container images and downloads `actionlint` at a
pinned version and checksum; the commands above assume the tools are installed locally and will
differ in version, which is the usual reason a local run and CI disagree.

`.bandit`, `.yamllint` and `.hadolint.yaml` at the repository root carry the thresholds and
the exceptions. A finding is fixed rather than suppressed unless the suppression carries a
comment saying why.

### The images

```
docker compose -f docker-compose.yaml up --build        # the prune environments
docker compose -f docker/run_phase/java/docker-compose.yaml up --build
```

Each prune container works independently on its language and writes its result into the
shared `var/tmp` mount; nothing passes between containers except through that directory.

### The host

The run phase installs nothing on the host and changes no host state. Landlock, the connect
guard and the timeout are all self-imposed by the unprivileged process, so there is no
profile to deploy and no root step. The one thing the grading container must add from
outside is `--network none` and cgroup limits, which Phobos cannot set for itself.

## Project structure

```
core/                      the sandbox itself
  phobos.sh                entry point: parses the configuration, applies the layers
  phobos-policysystem.sh   turns the base and exercise configuration into a run's specification
  phobos-filesystem.sh     the filesystem layer, reads the path sets and applies Landlock
  phobos-networksystem.sh  the network layer, runs the connect guard and the egress/inbound HAProxy
  phobos-timeoutsystem.sh  the timeout layer, which applies the group lock when a timeout is set
  phobos-resourcesystem.sh the resource layer, sets the rlimits the policy names, started by the filesystem layer right before Landlock
  phobos-landlock-filesystem-and-networksystem/  its *.c/.h: the C program that applies the Landlock policy, then exec's
  phobos-seccomp-networksystem/  its *.c/.h: the connect guard, supervises connect() and enforces [connect] by host and port
  phobos-seccomp-timeoutsystem/  its *.c: the group lock, a seccomp filter refusing setsid and setpgid, then exec's
  phobos-tools-common/     sourced by every layer through phobos-common.sh, which sources the rest here and the three per-subsystem helpers
    phobos-common.sh       the shared entry the layers source; it sources the others
    phobos-constants.sh    the numbers the scripts share, named once, the exit statuses among them
    phobos-log.sh          reporting, and counting what a run was denied
    phobos-paths.sh        the two canonical forms a path is compared in
    phobos-time.sh         the timeout contract: how a value is spelled and compared
    phobos-spec-dir.sh     the specification directory and its lifetime
  phobos-tools-policysystem/
    phobos-policy-parse.sh one cfg in, the parsed state and the specification files out
    config_doc.txt         the configuration format, documented
  phobos-tools-filesystem/
    phobos-rights.sh       a parsed policy to the --rights= arguments phobos-landlock-filesystem-and-networksystem takes
  phobos-tools-networksystem/
    phobos-haproxy.sh      the egress broker and inbound filter: turns [connect]/[accept] into an haproxy.cfg
    phobos-network-args.sh [connect] and [bind] to the TCP and UDP port rules Landlock enforces
  config/                  BaseLanguage-<lang>.cfg and TailPhobos.cfg, the shipped policy
docker/prune_phase/        one image per language, plus the orchestrator
docker/run_phase/          the image an exercise actually runs in
tests/                     the acceptance and probe suites
var/tmp/                   prune inputs, helpers and example outputs
```

## Coding conventions

- One variable or function declaration per line, in every language.
- British English in all prose, comments and messages.
- Every function in the core shell scripts (`core/*.sh` and `core/phobos-tools-*/*.sh`) says what it does and what it assumes about its environment.
  AGENTS.md states this in full.
- Shell is POSIX where it can be and bash where it must be; say which at the top of a file.
- A `shellcheck` directive carries a comment on the line above saying why the finding is
  acceptable here.
