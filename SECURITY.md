# Phobos Security Policy

## Supported Versions

Currently, the only supported version is whatever is on `main`. This is a research artefact
rather than a released product, so there are no release lines and no maintained release
branches.

## Deliberately dangerous code

Phobos is a sandbox, so parts of it exist to do things a normal project would avoid, and the
rest exists to take privileges away. None of the following is a vulnerability.

- `core/` applies the sandbox. `phobos.sh` and the scripts beside it construct a Bubblewrap
  invocation from an allow-list, mounting most of the filesystem away behind an empty tmpfs
  and binding back only what the allow-list names. Code that assembles mount arguments from a
  configuration file looks like path injection, and is the mechanism.
- `ld_preloader/` and the `libnetblocker.so` beside it intercept network calls through
  `LD_PRELOAD`, hooking name resolution and `connect` so that only allow-listed hosts are
  reachable. Function interposition of libc symbols is what the component is for.
- `docker/prune_phase/` runs the discovery phase, which deliberately breaks a build over and
  over: it hides a directory, runs the tests, and concludes from the failure that the
  directory was needed. Its orchestrator therefore starts processes and interprets their
  failures, and its output becomes the allow-list the sandbox later trusts.
- `deploy_seccomp_apparmor.sh` installs seccomp and AppArmor profiles, which requires
  privilege on the host it is run on.
- The Dockerfiles under `docker/` extend the Artemis test images and add Bubblewrap, which
  needs user namespaces available in the container.

A committed `libnetblocker.so` is a compiled artefact in version control. It is there so the
runtime images can be assembled without a compiler; the C source it is built from is in the
repository beside it.

## Threat model, in one paragraph

Phobos defends the *grading machine* against untrusted student code executed during a test
run. It does not defend the student's own submission from anything, and it is not a general
containment boundary against a determined attacker with local privilege. The allow-list is
derived empirically by the pruning phase, so it is only as tight as the reference exercises
that produced it: a resource no reference exercise touched is hidden, and a resource one of
them touched is permitted for every submission thereafter.

## Scope

A report is in scope when Phobos fails at what it claims to do, or when it causes harm nobody
asked for. Concretely:

- a submission reaching a file or a network host that the active allow-list does not permit
- the sandbox failing open, that is, running the tests unconfined while reporting success
- the pruning phase writing an allow-list that grants more than the runs it observed required
- privilege escalation out of the sandbox onto the host
- any defect in this repository's own scripts that damages the machine running them beyond
  the working tree they were pointed at

Out of scope: the deliberately dangerous code listed above, the need for privilege to install
host profiles, and anything that follows from running the discovery phase against a project
you were not willing to have repeatedly broken.

## Reporting a bug

If the problem relates to a bug that is associated with unexpected behaviour or
inconvenience or something non-critical is broken, simply report it as a bug and use the
[issues](https://github.com/ls1intum/phobos/issues) for that.

## Reporting a Vulnerability

If the problem relates to a vulnerability that could be used maliciously or is in another
way a security issue, please do not make the issue public. Instead, collect the following
information first:
- as with a bug report, describe how the vulnerability can be reproduced
- state the commit, the allow-list in use and the language environment the run used
- state the kernel and whether the run was inside a container, since the enforcement
  mechanism depends on both
- provide any additional information and context, if possible

Then report it through [GitHub's private vulnerability
reporting](https://github.com/ls1intum/phobos/security/advisories/new), which is enabled
on this repository. The report stays private while it is assessed and remediated.
