# The prune image is the run-phase image plus the observer, so a prune run goes through exactly
# the layers a grading run does. The base the run-phase image ships is replaced by one that grants
# nothing: the pruner builds every policy itself, from denials.
#
# Nothing is added under /root/.m2 or any other build-tool cache, so this image holds the
# run-phase image's artefacts byte for byte and a pruned policy names files grading will find.
# strace stays out of the run-phase image: it is the observer here and nowhere else.
ARG RUN_PHASE_IMAGE=phobos-run-phase:ci
FROM ${RUN_PHASE_IMAGE}

# strace is the observer (ptrace, no privileges); python3 runs the pruner. DL3008 is ignored
# repository-wide in .hadolint.yaml, for the reason given there.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    strace \
 && rm -rf /var/lib/apt/lists/*

RUN rm -f "${PHOBOS_HOME}"/Base*.cfg
COPY BasePrune.cfg ${PHOBOS_HOME}/BasePrune.cfg
