# Landlock acceptance run

Verifies the five guarantees of the Landlock-based Phobos in an **ordinary**
container: no `--privileged`, no `--cap-add`, no `--security-opt`.

```bash
# 1. build context (Dockerfile expects core/ plus netblocker.c side by side)
mkdir -p /tmp/ctx/config
cp core/*.sh core/phobos-landlock*.c core/phobos-landlock*.h core/allowedList.cfg /tmp/ctx/
cp core/config/*.cfg /tmp/ctx/config/
cp ld_preloader/netblocker.c /tmp/ctx/

# 2. image
docker build -f docker/run_phase/java/Dockerfile -t phobos-landlock:test /tmp/ctx

# 3. run (note: no security flags of any kind)
docker run --rm -v "$PWD/tests/landlock-acceptance:/testsuite:ro" \
  phobos-landlock:test bash /testsuite/run-tests.sh
docker run --rm -v "$PWD/tests/landlock-acceptance:/testsuite:ro" \
  phobos-landlock:test bash /testsuite/extra-tests.sh
```

`run-tests.sh` covers the five required properties, `extra-tests.sh` covers
sandbox inheritance, a non-root run, and the control probe showing that the
denial comes from Landlock rather than from file permissions.
