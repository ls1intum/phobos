# The prune image is the run-phase image plus the observer, so a prune run goes through exactly
# the layers a grading run does. The base the run-phase image ships is replaced by one that grants
# nothing: the pruner builds every policy itself, from denials.
#
# Nothing is added under /root/.m2 or any other build-tool cache, so this image holds the
# run-phase image's artefacts byte for byte and a pruned policy names files grading will find.
# strace and the containment probe stay out of the run-phase image: they are the pruner's tools here
# and nowhere else.
#
# Built from the repository root: docker build -f docker/prune_phase/layers/Dockerfile .
ARG RUN_PHASE_IMAGE=phobos-run-phase:ci

# The protection matrix's probe, compiled statically with the run-phase image's own compiler, so
# that under a final policy it needs execute and read on itself and on no library (A.6.4,
# containment checks).
FROM ${RUN_PHASE_IMAGE} AS probe
WORKDIR /build
COPY tests/integration/protection-matrix/probe.c /build/probe.c
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static -pthread -o /build/phobos-prune-probe /build/probe.c

FROM ${RUN_PHASE_IMAGE}

# strace is the observer (ptrace, no privileges); python3 runs the pruner. DL3008 is ignored
# repository-wide in .hadolint.yaml, for the reason given there.
# On a run-phase image that has a python3 already (the Python one), none is added beside it, so the
# prune image differs from the image it was built on by the observer and the probe alone.
RUN apt-get update && apt-get install -y --no-install-recommends strace \
 && if ! command -v python3 > /dev/null; then apt-get install -y --no-install-recommends python3; fi \
 && rm -rf /var/lib/apt/lists/*

RUN rm -f "${PHOBOS_HOME}"/Base*.cfg
COPY docker/prune_phase/layers/BasePrune.cfg ${PHOBOS_HOME}/BasePrune.cfg
# The language seeds an exercise's prune.json may name (var/tmp/helpers/layer_prune/seed.py): the one place a
# language's own needs enter a prune, never its code.
COPY docker/prune_phase/layers/seeds /usr/local/share/phobos-prune/seeds
COPY --from=probe /build/phobos-prune-probe /usr/local/libexec/phobos-prune-probe

# The pruner removes what its runs leave behind outside the working directory, so it runs only where
# it finds this, in a container that exists for the prune.
ENV PHOBOS_PRUNE_CONTAINER=1
