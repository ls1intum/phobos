<!-- markdownlint-configure-file { "MD041": false } -->
<!--
  MD041 (first line in a file should be a top-level heading) is disabled above, because
  this file opens with an unheaded summary paragraph on purpose: see the note before
  "Linked issues". A top-level heading here would be copied into every release
  description and duplicate the release title GitHub already shows.

  Release notes template for Phobos.

  GitHub does not prefill release notes the way it prefills a pull request, so copy the
  body of this file into the release description and fill it in. Keep every heading below
  and their order, so that consecutive releases stay comparable, and keep the opening
  summary unheaded.

  Scope: everything merged since the previous release tag. List them with
  `git log --oneline <previous-tag>..main` and read the bodies of the pull requests it
  names, since each one already answers "Problem" and both "Improvement" sections for its
  own change.

  "Problems", "Improvements from the user's perspective" and "Improvements from the
  maintainer's perspective" carry the same meaning as sections 1, 2 and 3 of
  PULL_REQUEST_TEMPLATE.md, aggregated over the whole release rather than a single
  change. That template's sections 4 and 5 (the testing manual and the suite results)
  have no counterpart here: they describe how one change was verified, which is a
  reviewer's concern rather than a reader's. Each section below states what to write when
  it does not apply.

  Write in British English. State figures you have verified, and leave out those you
  have not: a release note is read as a record.
-->

<!--
  At most three lines: what this release changes, and why it matters. No implementation
  detail, and no list of pull requests.
  Say plainly whether the release is breaking, in a clause, and leave the detail and the
  upgrade steps to "Breaking changes and migration" below. A reader who sees "breaking"
  in the opening paragraph knows to read on; one who only finds out at the bottom has
  usually decided already.
  Say plainly, too, whether this release changes what the sandbox permits. A reader
  running untrusted submissions needs that in the first three lines, not in a section
  further down.
  This section is always required and has no heading, so that it renders as the opening
  paragraph of the release.
-->

## Linked issues

<!--
  The issues this release closes or relates to, for example "Closes #123" or
  "Relates to #456", each with a few words on what it was.
  If no issue is involved, write "None".
-->

None.

## Problems

<!--
  What was wrong before this release, aggregated over every change in it. Group by the
  layer at fault where that helps a reader: the filesystem sandbox, the network filter,
  the timeout wrapper, the policy parser, the prune phase or the images.
  For anything that concerned the sandbox boundary, say which way round it went: Phobos
  let a submission reach something the policy forbids, or it blocked something a correct
  submission legitimately needs.
  This section is always required. If this release fixes nothing, write "None".
-->

## Improvements from the user's perspective

<!--
  Users are everyone who runs code under Phobos: students whose submissions execute
  inside the sandbox, tutors who have to make sense of a run that was cut short or
  denied something, and instructors who write the policy files and ship Phobos inside an
  exercise image.
  This section is always required. If this release gains this side nothing, write "None".
-->

## Improvements from the maintainer's perspective

<!--
  Maintainers are everyone who works on Phobos itself: contributors who change the
  scripts, the enforcement helper or the images, reviewers who have to judge whether the
  sandbox boundary still holds, and whoever publishes the images an exercise depends on.
  This section is always required. If this release gains this side nothing, write "None".
-->

## Breaking changes and migration

<!--
  Phobos is consumed as a container image plus the scripts under core/, so state
  explicitly whether this release changes any of:
  - the configuration file format, its sections or the meaning of an existing key
  - the command line of phobos.sh or of the layer scripts
  - the exit codes a caller relies on
  - the paths a policy has to name, or the paths that have to exist before a run
  - the kernel, container runtime or image requirements
  If it does, give the upgrade steps an instructor has to follow for an existing
  exercise. This is the section they read before upgrading.
  This section is always required. If the release is fully backwards compatible, write
  "No breaking changes or migration".
-->

No breaking changes or migration.

## Coordinates

<!--
  What a consumer has to pull for this version, so nobody has to construct it. Replace
  the tag in every line, and list one line per language image this release publishes.

  Publish these notes only once the images are actually live, which is a separate step
  from creating the GitHub release and can lag it. Confirm that every tag named here
  resolves before publishing: notes that name an image nobody can pull cost more
  goodwill than they buy.

  Where a release requires a minimum kernel, container runtime or host preparation, say
  so here rather than leaving a reader to discover it on first run.

  Close with the full changelog link, comparing the previous tag to this one.
-->

```bash
docker pull REPLACE_WITH_IMAGE:REPLACE_WITH_THIS_TAG
```

Requirements: REPLACE_WITH_KERNEL_AND_RUNTIME_REQUIREMENTS.

**Full changelog:** https://github.com/ls1intum/phobos/compare/REPLACE_WITH_PREVIOUS_TAG...REPLACE_WITH_THIS_TAG
