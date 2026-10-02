FROM python:3.14-slim@sha256:0741d101873c12ab927e6f8653feb8862b9bd58771177acb1b885b95141f91b4

WORKDIR /workspace

# The build context is this directory, which holds orchestrate.py.
COPY ./orchestrate.py .

ENTRYPOINT ["python3", "orchestrate.py"]
