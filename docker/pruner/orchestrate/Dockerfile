FROM python:3.15-slim@sha256:8c13a3f37a6a5b71498228e902c4b9f51c1f7900d49fabf71f9a650c6120e0d0

WORKDIR /workspace

# The build context is the repository root, where orchestrate.py lives under pruner/exercise_pruner/src/interface.
COPY pruner/exercise_pruner/src/interface/orchestrate.py .

ENTRYPOINT ["python3", "orchestrate.py"]
