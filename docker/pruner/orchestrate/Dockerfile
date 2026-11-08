FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

WORKDIR /workspace

# The build context is the repository root, where orchestrate.py lives under pruner/exercise_pruner/src/interface.
COPY pruner/exercise_pruner/src/interface/orchestrate.py .

ENTRYPOINT ["python3", "orchestrate.py"]
