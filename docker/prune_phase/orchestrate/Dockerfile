FROM python:3.14-slim

WORKDIR /workspace

# context = project root, so this path is inside it
COPY ./orchestrate.py .

ENTRYPOINT ["python3", "orchestrate.py"]
