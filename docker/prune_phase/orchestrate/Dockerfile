FROM python:3.14-slim@sha256:3353bb7e9ae99c7cce6cad2b2f2b174e8f22813ac43e3b13e7a742627d2b01d8

WORKDIR /workspace

# The build context is this directory, which holds orchestrate.py.
COPY ./orchestrate.py .

ENTRYPOINT ["python3", "orchestrate.py"]
