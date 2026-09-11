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
  inside a bind path and the sandbox does not start. Do not normalise the eight CRLF files
  as a side effect of another change; that is ls1intum/phobos#15.
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

**Sandbox application, at grading time.** The submission runs with only those paths mounted,
everything else replaced by empty tmpfs. Network access goes through a preload library that
intercepts name resolution and connection calls and permits only the hosts the discovery
phase recorded, with a Squid proxy available for the cases that need one. A timeout layer
bounds the run.

The point of the split is that the expensive, fragile part happens once per language
environment, offline, and grading itself only applies a fixed configuration.

## Tech Stack

- POSIX shell for the wrapper and the layers, which is the bulk of the repository
- C for the preload library, compiled inside the run-phase image
- Python for the prune orchestrator and the artefact helpers
- Docker for both phases, one image per language environment
- seccomp and AppArmor profiles for the host that runs the containers
- Java for exactly one file, `.github/scripts/CheckPullRequestTemplate.java`

Note that the filesystem enforcement mechanism is being changed on an open branch. Read
`core/phobos-filesystem.sh` on the branch you are working from rather than assuming which
mechanism is in force.

## Build and development commands

There is no build system. The shell runs as it is, and the C is compiled inside the image.

```
# Apply the sandbox to a command, using a language configuration
core/phobos.sh --config core/config/BaseLanguage-java.cfg -- ./gradlew test

# Layer switches, for isolating which layer a failure belongs to
core/phobos.sh --no-timeout --config ... -- <command>
```

### The linters, which are the gate

`lint.yml` runs six jobs and they are the whole of CI on `main` today. Run them before
opening a pull request.

```
shellcheck -x -S warning core/*.sh tests/*.sh    # or the pinned container image
cppcheck --enable=warning --error-exitcode=1 ld_preloader/*.c tests/*.c
ruff check .
bandit --recursive --ini .bandit --severity-level medium
yamllint --strict .
hadolint --config .hadolint.yaml docker/*/*/Dockerfile
```

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

### The host profiles

```
security_config/deploy_seccomp_apparmor.sh
```

This installs the seccomp and AppArmor profiles that allow the sandbox to run unprivileged
on the host. It needs root, and it changes host state; read it before running it.

## Project structure

```
core/                      the sandbox itself
  phobos.sh                entry point: parses the configuration, applies the layers
  phobos-filesystem.sh     the filesystem layer, reads the path sets and binds them
  phobos-network.sh        the network layer, drives the preload library
  phobos-timeout.sh        the timeout layer
  phobos-common.sh         shared helpers, sourced by the others
  config/                  BaseLanguage-<lang>.cfg and TailPhobos.cfg, the shipped policy
  libnetblocker.so         committed, binary in .gitattributes
ld_preloader/              netblocker sources and its own allow-list
security_config/           seccomp profile, AppArmor profile, host deployment script
squid/                     the egress proxy image and its configuration
docker/prune_phase/        one image per language, plus the orchestrator
docker/run_phase/          the image an exercise actually runs in
tests/                     the acceptance and probe suites
var/tmp/                   prune inputs, helpers and example outputs
assets/                    diagrams
```

## Coding conventions

- One variable or function declaration per line, in every language.
- British English in all prose, comments and messages.
- Every function in `core/*.sh` says what it does and what it assumes about its environment.
  AGENTS.md states this in full.
- Shell is POSIX where it can be and bash where it must be; say which at the top of a file.
- A `shellcheck` directive carries a comment on the line above saying why the finding is
  acceptable here.
