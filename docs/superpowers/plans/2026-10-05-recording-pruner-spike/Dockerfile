# Spike only, never shipped: the run-phase image plus the observer (strace) and the
# interpreter the prototype recorder is written in. It stands in for the prune image
# PR 162 introduces, so a recording is taken on the same filesystem a grading run sees
# and its policy is replayed through the very layers that grade.
ARG RUN_PHASE_IMAGE=phobos-run-phase:recorder-spike
FROM ${RUN_PHASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    strace \
 && rm -rf /var/lib/apt/lists/*
