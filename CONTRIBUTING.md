# Contributing to Phobos

Thank you for considering a contribution. Phobos is the sandbox that student code runs
inside on an interactive learning platform, so a change here has two ways to be wrong: it
can let a submission reach something it should not, or it can hide something a correct
submission legitimately needs and fail it. Both matter, and the second is the one that
tends to be discovered by an instructor rather than by a test.

Read [SECURITY.md](SECURITY.md) before you run anything. The discovery phase deliberately
breaks a build repeatedly, and `deploy_seccomp_apparmor.sh` changes host configuration.

## Identity and transparency

### Members of the organisation

1. **Real names required.** Use your full real name in your GitHub profile. This is a
   prerequisite for joining the organisation, and it is what makes accountability and open
   collaboration possible.
2. **Authentic profile picture.** Use a clear, professional photograph. Avoid comic-style
   pictures, memojis and other non-authentic styles.
3. **Branch directly in the repository.** Members create branches and pull requests here
   rather than in a fork.

### External contributors

1. **Identity verification.** External contributions are considered only when the
   contributor uses their real name and an authentic profile picture.
2. **Fork the repository** and work on a branch in your fork.
3. **Open a pull request** against `main` once the work is complete, with your branch up to
   date with `main`.

We align these expectations with the
[GitHub Acceptable Use Policies](https://docs.github.com/en/site-policy/acceptable-use-policies).
For general background on contributing to open source, see the
[Open Source Guides](https://opensource.guide/).

## Prerequisites

Phobos runs on Linux, because it depends on user namespaces and on `LD_PRELOAD`. Docker is
the supported way to work on it from another operating system; the Compose file in the
repository root brings up one container per language environment.

## Running the checks locally

The `Lint` workflow is the gate, and every one of its jobs can be run by hand:

```
shellcheck -x -S warning $(find . -name '*.sh' -type f)
gcc -fsyntax-only -Wall -Wextra -Werror -fanalyzer <file>.c
cppcheck --enable=warning --quiet --error-exitcode=1 <file>.c
ruff check --no-cache .
bandit --recursive --ini .bandit --severity-level medium docker/prune_phase/orchestrate var/tmp/helpers
yamllint --strict .
hadolint --config .hadolint.yaml < <Dockerfile>
actionlint
```

`shellcheck -x` matters: without it the shared library file is analysed in isolation and
every caller reports findings that are not real.

## Changing the sandbox

The allow-list is the security boundary, so a change that widens it needs to say why in the
pull request, not only in a commit message.

1. **Do not hand-edit a generated allow-list to make something work.** If a resource is
   genuinely needed, it should come out of the discovery phase; if it does not, that is a
   finding about the discovery phase.
2. **Say which language environments you re-pruned.** An allow-list produced for Java says
   nothing about Python, and a change that touches the shared configuration affects both.
3. **State the negative case.** A change is not verified by a passing exercise alone. Say
   what must still be blocked and how you confirmed it is.
4. **Rebuild `libnetblocker.so` from the source in this repository** if you change it, and
   say so, since the binary is committed.

## Changing the discovery phase

The pruning algorithm concludes from a failed test run that a hidden directory was needed.
Anything that changes how a failure is recognised therefore changes the allow-list. The
`NO-SOURCE` case in the existing code is the worked example: a build that reports success
while having compiled nothing has to be treated as a failure, or the pruner concludes that
the source directory was unnecessary.

## Pull requests

Fill in every section of the pull request template. The template checker runs on every pull
request and reports which section is missing or over its limit.

## Reporting problems

Open an issue. For a suspected vulnerability, use
[private vulnerability reporting](https://github.com/ls1intum/phobos/security/advisories/new)
rather than a public issue, as set out in [SECURITY.md](SECURITY.md).

## Code of conduct

Participation in this project is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md). By taking part you are expected to uphold it.
