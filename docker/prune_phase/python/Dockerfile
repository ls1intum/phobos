################################################################################
# docker/prune_phase/python/Dockerfile: the pruning-only image for Python exercises
#
#   • Installs just what the prune step needs: python3, pip, pytest, ruff and
#     bubblewrap, which the discovery phase measures with.
#   • Creates the same unprivileged  user  (sandboxuser) and runtime
#     directories used by the Java image, so your docker-compose mounts work
#     unchanged.
#   • Does *not* copy the pruning tool;   /var/tmp  is bind-mounted at runtime
#     by docker-compose and already contains the shared  pruning/  folder.
################################################################################

FROM ubuntu:26.04@sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        bubblewrap && \
    rm -rf /var/lib/apt/lists/*

# --break-system-packages because Ubuntu 26.04 ships a PEP 668 Python, which
# refuses to let pip write into the system installation. This is a disposable
# build container with no other Python in it, so there is nothing to protect and
# nothing a virtual environment would buy. Without the flag the image does not
# build at all: pip stops with externally-managed-environment.
RUN pip3 install --no-cache-dir --break-system-packages \
        pytest==9.1.1 \
        ruff==0.16.8

RUN useradd -m sandboxuser

RUN mkdir -p /home/sandboxuser/.cache/pip && \
    chown -R sandboxuser:sandboxuser /home/sandboxuser


USER sandboxuser

# docker-compose will append the language argument ("python") at run time.
ENTRYPOINT ["/var/tmp/pruning/run_minimal_fs_all.sh"]
