# The acceptance run

These suites apply the sandbox to real commands inside the run-phase image, in an
**ordinary** container: no `--privileged`, no `--cap-add`, no `--security-opt`, and
`--network none`. A suite that needed any of those would be measuring a different sandbox
from the one an exercise gets.

`build.yml` runs all eight on every change. To run them by hand:

```bash
# 1. build context (the same script CI uses, so the two cannot drift apart)
.github/scripts/assemble-run-phase-context.sh /tmp/ctx

# 2. image
docker build -f docker/run_phase/java/Dockerfile -t phobos-landlock:test /tmp/ctx

# 3. one suite, with no security flags of any kind and no network
docker run --rm --network none -v "$PWD/tests:/tests:ro" \
  phobos-landlock:test bash /tests/landlock-acceptance/run-tests.sh
```

Replace the last word with any of the suites below. Nothing is mounted over `/root/.m2`:
the base image ships a populated Maven repository, and a cache volume there hides it, so
the offline Maven steps then fail for want of a plugin, which looks like a sandbox failure
and is not one.

| Suite | What it proves |
| --- | --- |
| `run-tests.sh` | the five guarantees: an allowed path is readable, a forbidden one is not, a write outside the policy is refused, the restriction is inherited and cannot be shed, and a network endpoint the policy does not name is refused |
| `extra-tests.sh` | inheritance by a second process, a run as an unprivileged user, the control probe showing the denial comes from Landlock and not from file permissions, and the options no policy file reaches |
| `phase-test.sh` | rights tightened and widened across four phases of one Maven project, and the trap of an unrestricted final phase running what a restricted one left behind |
| `shipped-policy-test.sh` | the policy the image actually ships, rather than a policy written for the test, runs a real build |
| `network-port-test.sh` | a raw `connect()` syscall steps around the preload library, and Landlock's `--connect-tcp` rule refuses it anyway |
| `bind-address-test.sh` | a `[bind]` rule is enforced by port, by Landlock, and its local address by the preload library |
| `scoping-test.sh` | Landlock scoping: a sandboxed process can neither signal a process outside its domain nor reach an abstract UNIX socket there. Skipped below Landlock version 6 |
| `connect-guard-test.sh` | the connect guard in the image: an allowed destination connects, a forbidden one is refused, and a destination cannot be swapped after the check |

`PHOBOS_HOME` names where Phobos is installed in the image, `/var/tmp/opt/core` by
default. `tests/README.md` lists every suite of this repository, including the ones that
need no container.
