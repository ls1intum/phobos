# Phobos

**Run any program with only the access it was shown to need**

[![Build](https://github.com/ls1intum/phobos/actions/workflows/build.yml/badge.svg?event=push)](https://github.com/ls1intum/phobos/actions/workflows/build.yml)
[![Test](https://github.com/ls1intum/phobos/actions/workflows/test.yml/badge.svg?event=push)](https://github.com/ls1intum/phobos/actions/workflows/test.yml)
[![Lint](https://github.com/ls1intum/phobos/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/ls1intum/phobos/actions/workflows/lint.yml)
[![CodeQL](https://github.com/ls1intum/phobos/actions/workflows/codeql.yml/badge.svg?event=push)](https://github.com/ls1intum/phobos/actions/workflows/codeql.yml)
[![Documentation](https://github.com/ls1intum/phobos/actions/workflows/deploy-documentation.yml/badge.svg?event=push)](https://ls1intum.github.io/phobos/)
[![License: MIT](https://img.shields.io/github/license/ls1intum/phobos)](LICENSE)
![Linux](https://img.shields.io/badge/Linux-Landlock%20%2B%20seccomp-blue)

Phobos runs an arbitrary command with only the filesystem, network and resource access that
command was shown to need. It works in two phases: a discovery phase measures what a reference
workload actually uses, once per runtime environment and offline, and a protected run then
enforces exactly that. Grading a student submission is the use case it was written for, and an
untrusted build step, a data job or a third-party tool is the same problem.

- **A filesystem boundary enforced by Landlock**, with no privilege, no capability and no
  container flag
- **An outbound allow-list supervised by a seccomp connect guard**, by address and port, from
  outside the process
- **Host names enforced by an egress broker** that reads the Transport Layer Security host name,
  and inbound connections filtered by source address
- **A wall-clock timeout** nothing under it can step out of
- **Self-imposed resource limits** on memory, processes, open files, file size and processor
  time
- **A discovery phase that measures** what a program needs instead of guessing

## Installation

Phobos needs Linux, for Landlock and for seccomp user-notification. It is delivered as a
container image, which compiles the three C programs and puts the shipped policy where the
scripts look for it; a bare checkout is refused rather than run unprotected.

```bash
.github/scripts/assemble-run-phase-context.sh build/run-phase-context
docker compose -f docker/run_phase/java/docker-compose.yaml up --build
```

Then wrap a command with `phobos.sh`, inside that image:

```bash
${PHOBOS_HOME}/phobos.sh --config exercise.cfg -- ./gradlew test
```

Run the container with cgroup limits (`--memory`, `--pids-limit`, `--cpus`, and a size-bounded
`--tmpfs` for scratch) and whatever network isolation the deployment needs. Those are the outer
wall Phobos relies on and cannot set for itself.

## Documentation

📖 **<https://ls1intum.github.io/phobos/>**

- [User Documentation](https://ls1intum.github.io/phobos/user/phobos/what-is-phobos) — put a
  program in the sandbox, write a policy for it, and understand what Phobos does and does not
  protect against
- [Contributor Documentation](https://ls1intum.github.io/phobos/contributor/how-can-you-contribute) —
  the technologies Phobos is built on, the discovery phase and the subsystems

The documentation source lives in [`documentation/`](documentation/).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the checks, the rules
for changing the sandbox and the discovery phase, and the pull request process, and
[AGENTS.md](AGENTS.md) for the conventions a change here is held to. Participation is governed
by our [Code of Conduct](CODE_OF_CONDUCT.md).

Found a security vulnerability? Please do **not** open a public issue; follow
[SECURITY.md](SECURITY.md).

## Citing

If you use Phobos in your work, please cite it using the metadata in
[CITATION.cff](CITATION.cff).

## Licence

Phobos is licensed under the MIT Licence. See [LICENSE](LICENSE) for details. It is designed to
sit beneath [Ares 2](https://github.com/ls1intum/Ares2), which guards the language runtime the
operating system cannot see, and inside a container that supplies the hard resource caps.
