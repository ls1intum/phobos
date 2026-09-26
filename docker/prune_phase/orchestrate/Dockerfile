FROM python:3.14-slim@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d

WORKDIR /workspace

# The build context is this directory, which holds orchestrate.py.
COPY ./orchestrate.py .

ENTRYPOINT ["python3", "orchestrate.py"]
