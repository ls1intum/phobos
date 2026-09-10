# AGENTS.md

Repository conventions for automated agents and contributors working on Phobos. Every
convention lives here, stated once. [CLAUDE.md](./CLAUDE.md) imports this file and adds the
orientation an agent needs beside it: what the project is, how it is built, and where its
parts live.

## Read the open pull requests before you start

Phobos is under active, stacked change. At the time of writing, one branch replaces the
filesystem enforcement mechanism, another builds the run-phase image in CI and is stacked
on the first, and a third widens the analysis and pins what a build resolves. A change
written against `main` alone can be correct and still conflict with all three.

**Rule:** run `gh pr list` and read the bases before branching. A pull request whose base is
another branch rather than `main` is part of a stack; do not rebase it onto `main` yourself.

## The sandbox is the product, so never widen it quietly

Phobos exists to stop a submission reaching what it was not granted. Every change that makes
the sandbox permit more is a change to the security boundary, whether or not that was the
intention.

**Rule:**

- A change that permits something previously denied says so, in the pull request body, in
  the words "this now permits X, which it did not permit before". The template has a
  checklist line for exactly this claim.
- Prove both directions. A test that shows the permitted case still works proves nothing
  about containment; a test that shows the forbidden case is still denied proves nothing
  about usability. Changes need both.
- Never add a capability, a bind or an allowed host to make a test pass. That converts a
  containment failure into a widened boundary, and the suite goes green either way.
- The acceptance suites must run in an ordinary container with no `--privileged`, no
  `--cap-add` and no `--security-opt`. A suite that needs any of those is measuring a
  different sandbox from the one an exercise gets.

## Allow-list files are read line by line, so line endings are load-bearing

`core/phobos-filesystem.sh` reads the path sets with `while IFS= read -r p` and binds each
line as a path. A carriage return at the end of a line becomes part of the path, the bind
fails, and the sandbox does not start.

**Rule:**

- `*.cfg`, `*.paths`, `*.flags` and `*.rules` are LF. `.editorconfig` pins this and says why.
- This repository deliberately has no blanket `text=auto` rule, because eight files are
  stored with CRLF and normalising them is a behaviour change that needs a Docker build to
  verify. That work is tracked in ls1intum/phobos#15. Do not normalise them as a side
  effect of another change.
- To see the current set rather than trusting a list: `git ls-files --eol | grep crlf`.

## A prune run that fails for the wrong reason is worse than one that fails

The discovery phase decides what a submission is allowed to reach by hiding a directory and
observing whether the tests still pass. It therefore reads a test failure as "this was
needed". Anything that fails a run for an unrelated reason gets written into the allow-list
as a dependency.

**Rule:**

- A prune run must not reach the network for anything it did not intend to. A registry
  outage arriving as a sandbox regression is the failure mode this rule exists for: pin the
  versions a probe build resolves, so that a fetch is not a variable.
- Gradle reports `NO-SOURCE` with exit code zero. An exit code is not a result here. Read
  what the run produced.
- A pruning heuristic that treats an ambiguous outcome as "needed" produces a larger
  allow-list, which is a weaker sandbox that still looks like it works. Say in the pull
  request which direction a heuristic errs in.

## Compiled artefacts in version control

`core/libnetblocker.so` and `ld_preloader/libnetblocker.so` are committed. `.gitattributes`
marks `*.so` binary so that Git never applies text conversion to them.

**Rule:**

- Never let a text filter near them. A normalised shared object is a corrupted one.
- When the C sources change, say in the pull request whether the committed objects were
  rebuilt and how, or whether the image builds them. A stale `.so` beside changed sources is
  a defect that no test in this repository catches by itself.
- `.gitignore` covers `*.o` and `*.a`, not `*.so`, for that reason.

## Opening a pull request

Every pull request body must follow `.github/PULL_REQUEST_TEMPLATE.md`. **Read that file
before writing the body**, do not reconstruct it from memory or from another repository's
conventions.

**Why:** GitHub inserts the template only as a prefill in the web UI. Creating a pull request
from the command line with `gh pr create --body` or `--body-file` bypasses it entirely and
GitHub never validates the result, so an agent that has not read the template will silently
submit a body in the wrong shape. This is the single most common way an otherwise correct
contribution arrives unreviewable.

**Rule:**

- Build the body from the template. Fill in a copy and pass that as `--body-file`.
- Fill in every section. Use that section's documented phrase rather than deleting the
  section: `No linked issues`, `No Improvement from the user's perspective`, `No Improvement
  from the maintainer's perspective`, `No breaking changes or migration`, `No behaviour
  covered by the suites changed`, `Not reproducible from a run`, `No layer-specific
  behaviour changed`. Each phrase belongs to the section that documents it, so the wrong one
  does not answer a section, and neither does a shortened one.
- Five of those answer a whole section: `No linked issues`, the two `No Improvement from the
  ...'s perspective` phrases, `No breaking changes or migration` and `No behaviour covered by
  the suites changed`.
- Two answer a part of section 4 rather than the section: `Not reproducible from a run`
  belongs under Steps, and `No layer-specific behaviour changed` belongs to the layers. They
  do not finish section 4, and its limit and its stubs are checked either way.
- Do not delete, rename or reorder the `##` headings. The `pr-template` check knows them by
  name, so a renamed heading fails the check.
- Tick boxes as `[x]`. When a checklist item does not apply, wrap that line in an HTML
  comment stating the reason, so the diff still records that it was considered. The
  unprivileged-container line is the one most often ticked untruthfully; leave it unticked
  and say why in section 4 instead.
- Respect the character limit a section declares. Summary carries `Limit: 500 characters`;
  `Linked issues`, sections 1 to 3 and `Breaking changes and migration` carry `Limit: 1000
  characters`; section 4 carries `Limit: 5000 characters`, counted over the whole section
  including the layers below it. The count is in code points over the text left once every
  instruction comment the checker recognises is removed, so a comment kept in the body does
  not count towards it.

Check a body before opening the pull request, from the repository root:

```
PR_BODY="$(cat body.md)" java .github/scripts/CheckPullRequestTemplate.java
```

The checker is a single-file Java program, run through the source-code launcher of JDK 11 or
newer, so it needs no build step and adds no language to the repository. It is the only Java
here, which is why the CodeQL workflow analyses `java-kotlin`: the checker reads a pull
request body that an outsider writes verbatim.

**Only the template's own headings.** The check reports every line it reads as a heading that
the template does not define, sub-headings included. Whatever sits under an invented heading
is measured as part of the section above it.

**Changing the template is two edits, not one.** The required headings, the character limits
and the phrases that answer a section live in one ordered map, `SECTIONS`, at the top of
`.github/scripts/CheckPullRequestTemplate.java`. The checker does not read the template, so a
section renamed, added, removed, given a different limit or given a different whole-section
phrase has to be changed in both files in the same commit. Nothing detects the drift.

Pull requests opened by `renovate[bot]` or `dependabot[bot]` are exempt: their bodies are
generated by the tool and cannot follow the template.

## Documenting shell, C and Python

There is no Javadoc here, and the same standard applies anyway: say what a thing is and what
it is for, in the comment syntax the file has.

**Rule:**

- One field, variable or function declaration per line, in every language.
- Every function in `core/*.sh` carries a comment saying what it does and what it assumes
  about the environment it runs in. A sandbox wrapper that assumes a mount, a capability or
  an environment variable and does not say so is a trap for the next reader.
- No comments inside a function body. A function that needs one is a function that should be
  two, each named after the question it answers. A comment beside a constant is allowed.
- Say why, not what, wherever the why could be broken unknowingly. `--ro-bind` is obvious;
  the reason a particular path must be writable is not, and that reason is what a future
  editor would remove.
- Claim only what the code does. If a sentence would need a paragraph of exceptions, say the
  narrow true thing instead.
- `shellcheck` runs at `-S warning` with `-x`. A directive that silences a finding carries a
  comment saying why, on the line above it.

## British English

All prose, comments, documentation, workflow names, step names, labels and user-facing
messages use current British English. Programming-language syntax, dependency coordinates,
API names and quoted external identifiers keep whatever spelling the technology requires.
