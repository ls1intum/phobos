# AGENTS.md

Repository conventions for automated agents and contributors working on Phobos. Every
convention lives here, stated once. [CLAUDE.md](./CLAUDE.md) imports this file and adds the
orientation an agent needs beside it: what the project is, how it is built, and where its
parts live.

## Read the open pull requests before you start

Phobos often changes through stacked pull requests, each based on the branch of the one
before rather than on `main`. A change written against `main` alone can be correct and still
conflict with an open stack.

**Rule:** run `gh pr list` and read the bases before branching. A pull request whose base is
another branch rather than `main` is part of a stack; do not rebase it onto `main` yourself.
Every workflow filters its `pull_request` trigger on `main`, so a stacked pull request gets no
checks of its own: start `build.yml`, `lint.yml`, `test.yml` and `codeql.yml` on its branch with
`workflow_dispatch`, link the runs in the pull request, and run the template checker locally.

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

The policy itself is additive by design, and that is not a hole to close. Everything is denied
first, and the platform, language and exercise configurations each only widen the allow-list;
`phobos-policysystem.sh` folds every config, base and exercise alike, through `fs_union_dir`, so an
exercise config may add a path or a right the base did not grant. This rests on the exercise
configuration being trusted input that the graded code cannot write, which SECURITY.md states
as an integration requirement. Do not "fix" the union back to a narrow-only exercise merge:
that would break the intended platform/language/exercise layering, not tighten it.

### A base entry an ancestor already covers is not dead code

A shipped `Base*.cfg` lists paths that grant Landlock nothing beyond what an ancestor entry
already grants it: `BaseLanguage-java.cfg` names `/usr/bin` with `rx` under a `/usr` that is
already `rx`, and Landlock unions the rights of every rule along a path, so the nested rule
adds nothing to the ruleset. They look like clutter and they are not.

`fold_table_by_target` unions every row naming one target, and `resolve_rights_hierarchy` then
refuses a nested entry whose rights are a **strict subset** of an ancestor's, because Landlock
can never take a right away and the narrower entry would not hold. So the base row decides
whether an exercise config is accepted:

- with `/usr/bin rx` in the base, an exercise config naming `[read] /usr/bin` folds onto that
  row, the target holds `rx`, and the run starts;
- without it, the same exercise config is `r` beneath an `rx` ancestor, which is that strict
  subset, and the run ends at `PHB-EPOLICY` before the command is reached.

**Rule:** do not delete such an entry from a shipped policy as a tidy-up. It changes nothing
about what Landlock enforces and it changes which exercise configurations Phobos accepts,
which is a breaking change for whoever wrote them. Deleting one is a deliberate act that says
so in the pull request body and proves both directions.

What those entries do **not** do is make an arbitrary narrower subpath acceptable. They
preserve acceptance for exercise configurations that name exactly the paths they name, and
nothing else; a config naming some other path beneath a wider rule with fewer rights is still
refused. `tests/integration/filesystem_policy.sh` pins both directions of this, and
`tests/policy-redundancy-probe.sh` reports which entries of a policy are in this position,
which is worth reading when judging a freshly pruned one.

## Allow-list files are read line by line, so line endings are load-bearing

`core/phobos-filesystem.sh` reads the path sets with `while IFS= read -r p` and turns each
line into a Landlock rule. A carriage return at the end of a line becomes part of the path:
a read or execute path then names nothing that exists and is dropped, and a write path is
created under the wrong name, so the run silently loses access the policy granted.

**Rule:**

- Every text file is LF. `* text=auto eol=lf` in `.gitattributes` has Git store it that way,
  and `.editorconfig` asks editors for the same. `*.cfg`, `*.paths`, `*.flags` and `*.rules`
  are where a carriage return breaks the sandbox rather than a tool.
- Changing the line endings of a file something reads at run time is a behaviour change, so
  the pull request says how the result was verified, by a Docker build where the file is a
  Dockerfile.
- To see whether anything is stored with CRLF rather than trusting this file:
  `git ls-files --eol | grep crlf`.

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

## The compiled binaries

None of the C products is committed. `phobos-landlock-filesystem-and-networksystem`, the connect guard and the timeout's
group lock are built from the source under `core/`, once per architecture, inside the run-phase
image. `.gitattributes` marks `*.so` binary so that a stray shared object is never normalised,
though none is shipped.

**Rule:**

- Never check a compiled binary in. The `run-phase` job in `build.yml` builds the image for
  amd64 and arm64 on native runners and, on the copies each image ships, checks with `readelf`
  that all three are position-independent (`Type: DYN`) with full RELRO (`BIND_NOW`), so both
  architectures are proven on every run; publishing the multi-arch image is a manual step (below).
- Where the connect guard binary is missing the network layer ends the run with PHB-ERUNTIME
  rather than running without connect supervision, so a bare checkout with nothing built does
  not run: the delivery vehicle is the image.
- To rebuild and check the image locally, build it and run the acceptance suites inside it, as
  the run-phase job does; the exact commands are in the run-phase section of `build.yml` and in
  CLAUDE.md.

## Publishing the run-phase image

CI builds and tests the run-phase image on both architectures but does not publish it, so no
registry credentials live in the workflow. A maintainer publishes it by hand once CI is green,
to their own registry namespace (for example `markuspaulsen/phobos`), from the repository root:

```
CTX="$(mktemp -d)"
.github/scripts/assemble-run-phase-context.sh "$CTX"
docker login                 # to the registry the tag below names
docker buildx build --platform linux/amd64,linux/arm64 \
  -f docker/run_phase/java/Dockerfile -t <namespace>/phobos:latest --push "$CTX"
```

`buildx --push` builds both architectures and pushes one multi-arch manifest, so a `docker pull`
selects the puller's architecture. The per-architecture acceptance suites ran natively in CI;
this step only packages and publishes. An image that embeds Phobos, such as a grading image,
then pulls it with `COPY --from=<namespace>/phobos:latest`.
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
  from the maintainer's perspective`, `No breaking changes or migration`, `No production code
  changed`, `Not reproducible from a run`, `No layer-specific behaviour changed`. Each phrase
  belongs to the section that documents it, so the wrong one does not answer a section, and
  neither does a shortened one.
- Five of those answer a whole section: `No linked issues`, the two `No Improvement from the
  ...'s perspective` phrases, `No breaking changes or migration` and `No production code
  changed`.
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

## Publishing a release

Every release description must follow `.github/RELEASE_TEMPLATE.md`. **Read that file before
writing the notes**, do not reconstruct it from memory.

**Why:** GitHub does not prefill a release from the template the way it prefills a pull
request in the web UI, and nothing on GitHub validates the result. Creating a release from
the command line with `gh release create --notes` or `--notes-file` bypasses the template
entirely, so notes written from memory arrive in the wrong shape.

**Rule:**

- Build the notes from the template. Copy it into the release description and fill in every
  section.
- Keep the opening summary unheaded. The release opens with a paragraph of at most three
  lines; a top-level heading there would duplicate the release title GitHub already shows.
- Fill in every section. Where a section does not apply, use its documented phrase (`None`
  for `Linked issues` and for `Breaking changes and migration`, `No Improvement` for each of
  the two `Improvements` sections) rather than deleting the section.
- `Problems` is never answered with `None`. A release with nothing to say under Problems does
  not need notes; describe the gaps, limitations or maintenance it addresses instead.
- `## Coordinates` ships placeholders (`REPLACE_WITH_THIS_TAG`, `REPLACE_WITH_PREVIOUS_TAG`,
  `REPLACE_WITH_IMAGE`, `REPLACE_WITH_KERNEL_AND_RUNTIME_REQUIREMENTS`). Replace them all before publishing.
- Do not delete, rename or reorder the `##` headings. The check knows them by name, so a
  renamed heading fails it.

Check the notes before publishing, from the repository root:

```
RELEASE_BODY="$(cat notes.md)" java .github/scripts/CheckReleaseTemplate.java
```

The checker is a single-file Java program, run through the source-code launcher of JDK 11 or
newer, so it needs no build step and adds no language to the repository.

`release-template.yml` runs the same program on `release: published` and `release: edited`.
Read it as an alarm rather than a gate: the event fires once the release is already public,
and GitHub offers no event for a release while it is still a draft, so the workflow cannot
stop malformed notes from being published. It makes them visible immediately, and the command
above is what actually prevents them.

**Changing the template is two edits, not one.** The required headings and the phrases that
answer a section live in `SECTIONS` at the top of `.github/scripts/CheckReleaseTemplate.java`,
the opening line cap lives in `OPENING_MAX_LINES` beside it, and the closing section whose
placeholders are checked is named in `PLACEHOLDER_SECTION`. The checker does not read the
template, so a section renamed, added, removed or given a different whole-section phrase, or a
changed opening cap, has to be changed in both files in the same commit. Nothing detects the
drift.

## Documenting shell, C and Python

There is no Javadoc here, and the same standard applies anyway: say what a thing is and what
it is for, in the comment syntax the file has.

**Rule:**

- One field, variable or function declaration per line, in every language.
- Every function in the core shell scripts (`core/*.sh` and `core/phobos-tools-*/*.sh`)
  carries a comment saying what it does and what it assumes about the environment it runs in.
  A sandbox wrapper that assumes a mount, a capability or an environment variable and does not
  say so is a trap for the next reader.
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
