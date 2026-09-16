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
  inside a bind path and the sandbox does not start. Every text file is stored with LF, and
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

**Sandbox application, at grading time.** The submission runs with only those paths mounted,
everything else replaced by empty tmpfs. Network access goes through a preload library that
intercepts name resolution and connection calls and permits only the hosts the discovery
phase recorded, with a Squid proxy available for the cases that need one. A timeout layer
bounds the run.

The point of the split is that the expensive, fragile part happens once per language
environment, offline, and grading itself only applies a fixed configuration.

## Tech Stack

- POSIX shell for the wrapper and the layers, which is the bulk of the repository
- C for the preload library and for `phobos-landlock`, both compiled inside the run-phase image
- Python for the prune orchestrator and the artefact helpers
- Docker for both phases, one image per language environment
- Java for exactly one file, `.github/scripts/CheckPullRequestTemplate.java`

The filesystem layer is enforced by Landlock, an unprivileged Linux kernel sandbox, applied
by `phobos-landlock` (the C program under `core/`). The run phase needs no privileges, no
capabilities and no container flags. The discovery phase still uses Bubblewrap to hide
directories while it measures; the sandbox an exercise runs in does not.

## Build and development commands

There is no build system. The shell runs as it is, and the C is compiled inside the image.

```
# Apply the sandbox to a command, using a language configuration
core/phobos.sh --config core/config/BaseLanguage-java.cfg -- ./gradlew test

# Layer switches, for isolating which layer a failure belongs to
core/phobos.sh --no-runtime-restriction --config core/config/BaseLanguage-java.cfg -- <command>
```

### The linters, which are the gate

`lint.yml` runs six lint jobs. It is not the whole of CI: `test.yml` runs the shell and
Python suites, `build.yml` builds the images and holds the run-phase image to the Landlock
acceptance suites inside it, `codeql.yml` scans, and `pullrequest-template.yml` checks the
body. The lint jobs are the ones you can run in full by hand before opening a pull request.

```
# Same file sets as CI. Each of these is the whole job, not a sample of it.
find . -name '*.sh'  -type f -print0 | xargs -0 shellcheck -x -S warning
find . -name '*.c'   -type f -print0 | xargs -0 cppcheck --enable=warning --quiet --error-exitcode=1
ruff check --no-cache .
bandit --recursive --ini .bandit --severity-level medium docker/prune_phase/orchestrate var/tmp/helpers
yamllint --strict .
find . -name 'Dockerfile*' -type f -exec sh -c 'hadolint --config .hadolint.yaml < "$1"' _ {} \;
```

Two of those are narrower than they look. `bandit` runs over exactly two directories, not the
whole tree, because everything else Python here is fixture. `hadolint` matches `Dockerfile*` at
any depth, but `-name` anchors at the start of the base name, so it reaches the five under
`docker/` and not `squid/HTTP_PROXY_SQUID_Dockerfile`. That exclusion is deliberate: that file
fails hadolint and cannot build either, because it copies directories this repository does not
have. Repairing or deleting it is a decision about the file rather than about linting. CI runs
shellcheck, cppcheck and hadolint inside pinned container images; the commands above assume the
tools are installed locally and will differ in version, which is the usual reason a local run
and CI disagree.

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

The run phase installs nothing on the host and changes no host state. Landlock, the preload
library and the timeout are all self-imposed by the unprivileged process, so there is no
profile to deploy and no root step. The one thing the grading container must add from
outside is `--network none` and cgroup limits, which Phobos cannot set for itself.

## Project structure

```
core/                      the sandbox itself
  phobos.sh                entry point: parses the configuration, applies the layers
  phobos-filesystem.sh     the filesystem layer, reads the path sets and applies Landlock
  phobos-landlock*.c/.h    the C program that applies the Landlock policy, then exec's
  phobos-network.sh        the network layer, drives the preload library
  phobos-resources.sh      the resource layer, sets the rlimits the policy names
  phobos-timeout.sh        the timeout layer
  phobos-common.sh         shared helpers, sourced by the others
  config/                  BaseLanguage-<lang>.cfg and TailPhobos.cfg, the shipped policy
ld_preloader/              netblocker sources, its own allow-list, and the library built from them
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
