FROM python:3.15-slim@sha256:533b0b2f9b5d46fd097091cf826f27902f1d6c3bca714b6dc74551356aa97a51

WORKDIR /workspace

# The build context is the repository root, where orchestrate.py lives under pruner/exercise_pruner/src/interface.
COPY pruner/exercise_pruner/src/interface/orchestrate.py .

ENTRYPOINT ["python3", "orchestrate.py"]
