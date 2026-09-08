<!-- markdownlint-disable-file MD041 -->
<!--
  Thanks for contributing to Phobos.
  Fill in every section. Each section states what to write when it does not apply.
  Tick boxes as [x], not [ x] and not [x ].
  Write in British English.

  Each recurring instruction is repeated, in the same words, in every section where it
  applies, so that reading the one section you are filling in is enough. They close every
  section comment, after whatever that section says for itself, and always in this order:
  1. "This section is always required" says so, and then says what to write when it does
     not apply to your change. Every section is required, so a section that does not
     apply is answered rather than deleted.
  2. "Limit" says how long the section may be, where there is a limit.
  3. "Simple words" says who has to be able to follow the section.
-->

## Summary

<!--
  What changes, and why it matters. No implementation detail.

  This section is always required. There is no change it does not apply to.

  Limit: 500 characters, counted over the text left once every instruction comment such
  as this one is removed, so keeping the comment costs nothing.

  Simple words: write this so that an instructor who does not know the inside of Phobos
  can follow it. Spell out any Phobos term you cannot avoid. Say less, not more: a
  reviewer who cannot follow a short answer will ask, and the detail belongs in the code
  or in the linked issue.
-->

## Linked issues

<!--
  For example "Closes #123" or "Relates to #456".

  This section is always required. If this pull request relates to no issue, write
  "No linked issues".

  Limit: 1000 characters, counted over the text left once every instruction comment such
  as this one is removed, so keeping the comment costs nothing.
-->

## 1. Problem

<!--
  What is wrong today?
  Useful to cover:
  - What did you see, and in which setup (which language image, which base policy, which
    kernel and which container runtime)?
  - What should have happened instead?
  - Which layer of Phobos is at fault? Name it. Examples, not a complete list: the
    filesystem sandbox that decides which paths a submission may reach, the LD_PRELOAD
    network filter that decides which hosts it may contact, the timeout wrapper that
    stops a run that never finishes, the policy parser and the per-path merge that turn
    configuration files into an effective allow-list, the prune phase that discovers
    which paths a language environment actually needs, or the container images the run
    phase is built from. If the part you mean is not listed, name it in your own words.
    A reviewer of a sandbox needs to know where to look, so name it even where the rest
    stays plain.
  - Why does it matter? If something is broken, say which way round it went: Phobos let
    a submission reach something the policy forbids, or it blocked something a correct
    submission legitimately needs.

  This section is always required. If nothing is broken, describe the gap or the extra
  work that made you open this pull request instead.

  Limit: 1000 characters, counted over the text left once every instruction comment such
  as this one is removed, so keeping the comment costs nothing.

  Simple words: write this so that an instructor who does not know the inside of Phobos
  can follow it. Spell out any Phobos term you cannot avoid. Say less, not more: a
  reviewer who cannot follow a short answer will ask, and the detail belongs in the code
  or in the linked issue.
-->

## 2. Improvement from the user's perspective

<!--
  Users are everyone who runs code under Phobos: students whose submissions execute
  inside the sandbox, tutors who have to make sense of a run that was cut short or
  denied something, and instructors who write the policy files and ship Phobos inside an
  exercise image.
  Say what gets better for them, for example a clearer denial message, fewer correct
  submissions stopped by mistake, a rule that could not be expressed before, a faster
  run, or a newly supported language environment.

  This section is always required. If this side gains nothing from this pull request,
  write "No Improvement from the user's perspective".

  Limit: 1000 characters, counted over the text left once every instruction comment such
  as this one is removed, so keeping the comment costs nothing.

  Simple words: write this so that an instructor who does not know the inside of Phobos
  can follow it. Spell out any Phobos term you cannot avoid. Say less, not more: a
  reviewer who cannot follow a short answer will ask, and the detail belongs in the code
  or in the linked issue.
-->

## 3. Improvement from the maintainer's perspective

<!--
  Maintainers are everyone who works on Phobos itself: contributors who change the
  scripts, the enforcement helper or the images, reviewers who read those changes and
  have to judge whether the sandbox boundary still holds, and whoever publishes the
  images an exercise then depends on.
  Say what gets better for them, for example less duplicated code, a clearer structure,
  a flaky test removed, better diagnostics when a run is denied, less manual release
  work, or a simpler CI setup.

  This section is always required. If this side gains nothing from this pull request,
  write "No Improvement from the maintainer's perspective".

  Limit: 1000 characters, counted over the text left once every instruction comment such
  as this one is removed, so keeping the comment costs nothing.

  Simple words: write this so that an instructor who does not know the inside of Phobos
  can follow it. Spell out any Phobos term you cannot avoid. Say less, not more: a
  reviewer who cannot follow a short answer will ask, and the detail belongs in the code
  or in the linked issue.
-->

## 4. Testing manual

<!--
  Write these steps so that a reviewer who did not write the code can follow them from a
  cold start.

  Fewest steps, fewest tools. Count what you are asking for before you ask: every
  install, every image build, every command line is a reason the manual goes untried,
  and a change nobody tested is a change nobody reviewed.

  State the container invocation in full, and state it exactly. Phobos is a sandbox, so
  whether a run used --privileged, --cap-add or --security-opt is not a detail: a manual
  that leaves it out cannot tell a reviewer whether the boundary held or whether it was
  simply switched off. Where the change is meant to work in an ordinary container, have
  the reviewer run it in one and say so.

  Describe the action, not the controls it happens to use today. Before sending a
  reviewer to a result, check what they can see with the access they are likely to have,
  which is not yours.

  Start from a runnable image, do not make the reviewer build an exercise. docker/
  run_phase/ holds the language images; point at one of them and describe only the
  delta.

  Prerequisites: which branch to build, which base policy and which exercise
  configuration to pass, the kernel and container runtime the steps assume, and anything
  that has to exist on the host before the run.

  Steps: numbered, one observable result per step, with the exact commands where there
  are commands. A step a reviewer cannot check the outcome of is setup, not a step.

  Expected result: state it per step, not once for the whole scenario. Say what must be
  observable, and where: name the log line, the exit code or the file the reviewer
  should read. Give both directions. A sandbox change is only tested when a reviewer has
  seen the forbidden thing denied AND the permitted thing still working, because a
  sandbox that denies everything passes every one-sided manual.

  Have the reviewer look at the result, not only at an exit code. A command that exits
  zero says the command ran. It does not say that what it produced is right, and a
  manual made of green commands asks a reviewer to review your exit codes rather than
  your change. Every claim in section 2 needs a step where the thing itself is in front
  of them: the denial in the log, the file that could or could not be written, the exit
  status the caller sees. Name what they must see there, and name what would be wrong.

  This matters most where a run cannot see the defect. A build passes cleanly while the
  sandbox was never applied, a policy is read without complaint while the rule it was
  meant to express is not enforced, and a suite reports passes while only ever asserting
  denials. Where a suite in this repository already looks at such a result for you, run
  it as a step and say what it covers, rather than leaving a reviewer to assume the run
  covered it.

  Negative case: equally important for a sandbox. State what must still be rejected, and
  how a reviewer confirms that Phobos has not become more permissive.

  A step nobody can follow is a step nobody runs.

  The limit below covers this whole section, the layers at the end of it included.

  This section is always required. If the change cannot be exercised from a run (for
  example a CI workflow or documentation change), write "Not reproducible from a run"
  under Steps and describe instead how a reviewer verifies the change, for example which
  workflow run to inspect.

  Limit: 5000 characters, counted over the text left once every instruction comment such
  as this one is removed, so keeping the comment costs nothing.

  Simple words: write this so that an instructor who does not know the inside of Phobos
  can follow it. Spell out any Phobos term you cannot avoid. Say less, not more: a
  reviewer who cannot follow a short answer will ask, and the detail belongs in the code
  or in the linked issue.
-->

**Prerequisites**

1.

**Steps**

1.

**Expected result**

**Negative case (what must still be rejected)**

**Layers exercised**

<!--
  Phobos composes three layers, and each can be disabled on its own. Tick the ones you
  verified, and say below why a subset is sufficient if you did not verify all of them.

  This part is always required. If the change cannot alter layer-specific behaviour,
  tick nothing and write "No layer-specific behaviour changed".
-->

- [ ] Filesystem layer
- [ ] Network layer
- [ ] Timeout layer
- [ ] All three together, as a run uses them by default

## 5. Test case coverage regarding this PR

<!--
  Phobos is tested by the suites under tests/. List every suite this pull request adds
  or changes, and every suite that covers the behaviour it changes, with the result of
  the run you actually did.

  Give the numbers the suite prints, not a summary of them: passed, failed and skipped.
  A skipped check is not a passing check, so say why it was skipped.

  State both directions per behaviour, not a total. The suites here assert that a denied
  path stays denied and that an allowed path keeps working, and only the pair says the
  boundary is where the policy puts it. A run that reports passes without saying which
  direction each one covered cannot be read.

  Say where the run happened: which container invocation, which kernel, and which
  architecture. The enforcement mechanism depends on all three, so a result without them
  cannot be reproduced or compared.

  This section is always required. If this pull request changes no behaviour that the
  suites cover (documentation, CI or build configuration only), replace the table with
  "No behaviour covered by the suites changed".
-->

| Suite | Passed | Failed | Skipped | What it covers regarding this PR |
| --- | ---: | ---: | ---: | --- |
|  |  |  |  |  |

## Breaking changes and migration

<!--
  Phobos is consumed as a container image plus the scripts under core/, so state
  explicitly whether this changes any of:
  - the configuration file format, its sections or the meaning of an existing key
  - the command line of phobos.sh or of the layer scripts
  - the exit codes a caller relies on
  - the paths a policy has to name, or the paths that have to exist before a run
  - the kernel, container runtime or image requirements
  If it does, describe what an instructor has to do to upgrade an existing exercise.

  This is the section an instructor reads before upgrading.

  This section is always required. If the change is fully backwards compatible, write
  "No breaking changes or migration".

  Limit: 1000 characters, counted over the text left once every instruction comment such
  as this one is removed, so keeping the comment costs nothing.

  Simple words: write this so that an instructor who does not know the inside of Phobos
  can follow it. Spell out any Phobos term you cannot avoid. Say less, not more: a
  reviewer who cannot follow a short answer will ask, and the detail belongs in the code
  or in the linked issue.
-->

No breaking changes or migration.

## Checklist

<!--
  Tick what you have actually done, not what you intend to do. Each box is a claim a
  reviewer may check, and an untrue tick costs more trust than an untidy pull request.
  A task that applies but is not done stays unticked, with the reason said out loud in
  the section it belongs to, rather than ticked to make the list look finished.

  This section is always required. If a task does not apply, wrap its line in an HTML
  comment and state the reason inside the comment, rather than deleting or unticking it.
-->

- [ ] The title of this pull request describes the change, not the implementation.
- [ ] I have self-reviewed the diff of this pull request.
- [ ] Tests were added or updated for the behaviour changed here, in both directions: the forbidden case stays denied and the permitted case still works.
- [ ] Any weakening of the sandbox boundary is stated explicitly above, including what it now permits that it did not permit before.
- [ ] The change was exercised in a container started without `--privileged`, `--cap-add` or `--security-opt`, or the manual says why that was not possible.
- [ ] Documentation (`README.md`, the comments in `core/`) was updated where the change is user-facing.
- [ ] CI is green, or every remaining failure is explained above.
- [ ] No secrets, tokens or absolute local paths are contained in the diff.

## Review progress

<!--
  Reviewers tick what they have reviewed. Both boxes should be ticked before merge.

  This section is always required. If a category does not apply, wrap its line in an HTML
  comment and state the reason inside the comment, rather than deleting it.
-->

- [ ] Code review
- [ ] Manual test
