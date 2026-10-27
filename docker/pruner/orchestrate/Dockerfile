FROM python:3.15-slim@sha256:f786b2e19cf9bb54e96bfcd4c1b40c4c56336c22e60607ffd4b080ae5b5dee83

WORKDIR /workspace

# The build context is the repository root, where orchestrate.py lives under pruner/exercise_pruner/src/interface.
COPY pruner/exercise_pruner/src/interface/orchestrate.py .

ENTRYPOINT ["python3", "orchestrate.py"]
