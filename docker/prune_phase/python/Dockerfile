################################################################################
# docker/python/Dockerfile  – pruning-only image for Python exercises
#
#   • Installs just what the prune step needs: python3, pip, pytest, ruff,
#     bubblewrap, tree.
#   • Creates the same unprivileged  user  (sandboxuser) and runtime
#     directories used by the Java image, so your docker-compose mounts work
#     unchanged.
#   • Does *not* copy the pruning tool;   /var/tmp  is bind-mounted at runtime
#     by docker-compose and already contains the shared  pruning/  folder.
################################################################################

FROM ubuntu:26.04@sha256:513c074113a871b51a8d16ab445c88779d6452d937a164fb5cc479f32668a41d

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        bubblewrap tree && \
    rm -rf /var/lib/apt/lists/*

# --break-system-packages because Ubuntu 26.04 ships a PEP 668 Python, which
# refuses to let pip write into the system installation. This is a disposable
# build container with no other Python in it, so there is nothing to protect and
# nothing a virtual environment would buy. Without the flag the image does not
# build at all: pip stops with externally-managed-environment.
RUN pip3 install --no-cache-dir --break-system-packages \
        pytest==8.4.2 \
        ruff==0.8.1

RUN useradd -m sandboxuser

RUN chown -R sandboxuser:sandboxuser /var/tmp

RUN mkdir -p /home/sandboxuser/.cache/pip && \
    chown -R sandboxuser:sandboxuser /home/sandboxuser


USER sandboxuser

# docker-compose will append the language argument ("python") at run time.
ENTRYPOINT ["/var/tmp/pruning/run_minimal_fs_all.sh"]
