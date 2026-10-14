FROM python:3.15-slim@sha256:f48fda6d59b2b3437781d1c3ccf4aa0e26ae871de3cdd758b49ab45ee7291619

WORKDIR /workspace

# The build context is the repository root, where orchestrate.py lives under pruner/exercise_pruner/src/interface.
COPY pruner/exercise_pruner/src/interface/orchestrate.py .

ENTRYPOINT ["python3", "orchestrate.py"]
