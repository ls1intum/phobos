---
title: "How can you contribute"
sidebar_position: 1
description: "What a change to a sandbox has to prove, how to run the gate locally, and how a pull request is shaped."
---

:::tip[Simple Story]
A change here has two ways to be wrong.

It can let a command reach something it should not, and it can hide something a correct command
legitimately needs. The first is found by a reviewer; the second is found by whoever is using
Phobos, weeks later.
:::

Phobos is the sandbox, so every change is a change to a security boundary whether or not that
was the intention. Read
[SECURITY.md](https://github.com/ls1intum/phobos/blob/main/SECURITY.md) before you run
anything: the discovery phase deliberately breaks a build repeatedly, while a protected run
changes no host state at all.

The full conventions live in
[AGENTS.md](https://github.com/ls1intum/phobos/blob/main/AGENTS.md) and
[CONTRIBUTING.md](https://github.com/ls1intum/phobos/blob/main/CONTRIBUTING.md). This page is
the orientation beside them.

## Before you branch

Phobos often changes through stacked pull requests, each based on the branch of the one before
rather than on `main`. A change written against `main` alone can be correct and still conflict
with an open stack. Run `gh pr list` and read the bases first. A pull request whose base is
another branch is part of a stack, and it gets no checks of its own, because every workflow
filters its `pull_request` trigger on `main`: start `build.yml`, `lint.yml`, `test.yml` and
`codeql.yml` on its branch with `workflow_dispatch` and link the runs.

## Never widen the sandbox quietly

- A change that permits something previously denied says so, in the pull request body, in the
  words "this now permits X, which it did not permit before". The template has a checklist line
  for that claim.
- Prove both directions. A test showing the permitted case still works proves nothing about
  containment, and a test showing the forbidden case is still denied proves nothing about
  usability.
- Never add a capability, a bind or an allowed host to make a test pass. That turns a
  containment failure into a widened boundary, and the suite goes green either way.
- The acceptance suites must run in an ordinary container, with no `--privileged`, no
  `--cap-add` and no `--security-opt`. A suite needing any of those measures a different
  sandbox from the one a command gets.

The policy model is additive by design, and that is not a hole to close. Everything is denied
first, and the platform, language and task configurations each only widen. An exercise
configuration may add a path the base did not grant, which rests on that configuration being
trusted input the sandboxed command cannot write.

### A base entry an ancestor already covers is not dead code

A shipped base configuration lists paths that grant Landlock nothing beyond what an ancestor
already grants. They look like clutter and they are not: the base row decides whether a task
configuration naming exactly that path is accepted, because a nested entry with a strict subset
of an ancestor's rights is refused. Deleting one changes nothing about what Landlock enforces
and changes which configurations Phobos accepts.

`tests/filesystem_policy.sh` pins both directions of this, and `tests/policy-redundancy-probe.sh`
reports which entries of a policy are in this position.

## Line endings are load-bearing

The path sets are read with `while IFS= read -r`, so a carriage return ends up inside a path:
a read or execute path then names nothing that exists and is dropped, and a write path is
created under the wrong name. The run silently loses access the policy granted.

Every text file is stored with a line feed alone. `.gitattributes` has Git store it that way
and `.editorconfig` asks editors for the same. Check with `git ls-files --eol | grep crlf`.

## The gate

`lint.yml` runs eight jobs, and every one can be run by hand. The commands below are all eight,
run against locally installed tools. That is the usual reason a local run and the run in
continuous integration (CI) disagree on a version. The C job is two steps rather than one: the
compiler gate runs before cppcheck and fails on any warning.

```bash
find . -name '*.sh'  -type f -print0 | xargs -0 shellcheck -x -S warning
( failed=0; while IFS= read -r f; do gcc-14 -std=gnu23 -fsyntax-only -Wall -Wextra -Werror -fanalyzer "$f" || failed=1; done < <(find . -name '*.c' -type f); exit "$failed" )
find . -name '*.c'   -type f -print0 | xargs -0 cppcheck --std=c23 --enable=warning --quiet --error-exitcode=1
ruff check --no-cache .
bandit --recursive --ini .bandit --severity-level medium docker/prune_phase/orchestrate var/tmp/helpers
yamllint --strict .
find . -name 'Dockerfile*' -type f -exec sh -c 'hadolint --config .hadolint.yaml < "$1"' _ {} \;
actionlint
ec --no-color
awk 'FNR==1{p=""} /^[a-zA-Z_][a-zA-Z0-9_]*\(\)/{if(p !~ /^[[:space:]]*#/){print FILENAME":"FNR; e=1}} {p=$0} END{exit e}' core/*.sh
```

`shellcheck -x` matters: without it the shared library is analysed in isolation and every
caller reports findings that are not real. The last command is the `conventions` job, which
checks that every function in `core/*.sh` carries a comment above it.

This documentation has a gate of its own, run by `documentation-ci.yml`:

```bash
cd documentation
pnpm install --frozen-lockfile
pnpm run lint:code      # ESLint over the site sources
pnpm run test:prose     # the prose scanner's own tests
pnpm run test:structure # the twelve Policy Reference pages still share one example
pnpm run lint:prose     # the writing rules
pnpm run typecheck
pnpm run build          # onBrokenLinks and onBrokenAnchors are set to throw
pnpm run test           # Playwright, against the built site
```

## Documenting shell, C and Python

- One field, variable or function declaration per line, in every language.
- Every function in `core/*.sh` carries a comment saying what it does and what it assumes about
  the environment it runs in. A sandbox wrapper that assumes a mount, a capability or an
  environment variable and does not say so is a trap for the next reader.
- No comments inside a function body. A function that needs one is a function that should be
  two.
- Say why, not what, wherever the why could be broken unknowingly.
- Claim only what the code does. Where a sentence would need a paragraph of exceptions, say the
  narrow true thing instead.
- Every `shellcheck` directive carries a comment above it saying why the finding is acceptable.
- British English in all prose, comments, workflow names and messages.

## Opening a pull request

Build the body from `.github/PULL_REQUEST_TEMPLATE.md`, and read that file rather than
reconstructing it. GitHub inserts the template only as a prefill in the web interface, so
`gh pr create --body` bypasses it silently and nothing validates the result.

```bash
PR_BODY="$(cat body.md)" java .github/scripts/CheckPullRequestTemplate.java
```

The checker is a single-file Java program run through the source-code launcher of
Java Development Kit (JDK) 11 or newer, so it needs no build step. Fill in every section, use each
section's own escape phrase where it does not apply rather than deleting the section, keep the
headings verbatim, and respect the character limit each section declares.

## Further reading

- [Testing conventions](testing-conventions.md) — what the suites prove and how they report
- [Life of a sandboxed run](life-of-a-sandboxed-run.md) — the chain a change moves through
- [Pruning](pruning.md) — the discovery phase, and what a change there does to an allow-list
