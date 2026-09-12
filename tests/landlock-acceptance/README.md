# Landlock acceptance run

Verifies the five guarantees of the Landlock-based Phobos in an **ordinary**
container: no `--privileged`, no `--cap-add`, no `--security-opt`.

```bash
# 1. build context (the same script CI uses, so the two cannot drift apart)
.github/scripts/assemble-run-phase-context.sh /tmp/ctx

# 2. image
docker build -f docker/run_phase/java/Dockerfile -t phobos-landlock:test /tmp/ctx

# 3. run (note: no security flags of any kind, and no network either)
docker run --rm --network none -v "$PWD/tests/landlock-acceptance:/testsuite:ro" \
  phobos-landlock:test bash /testsuite/run-tests.sh
docker run --rm --network none -v "$PWD/tests/landlock-acceptance:/testsuite:ro" \
  phobos-landlock:test bash /testsuite/extra-tests.sh
docker run --rm --network none -v "$PWD/tests/landlock-acceptance:/testsuite:ro" \
  phobos-landlock:test bash /testsuite/phase-test.sh
```

`phase-test.sh` tightens and widens the rights across four phases in one container.
Every step of it is offline, so a run needs no network at all.

`run-tests.sh` covers the five required properties, `extra-tests.sh` covers
sandbox inheritance, a non-root run, and the control probe showing that the
denial comes from Landlock rather than from file permissions.
