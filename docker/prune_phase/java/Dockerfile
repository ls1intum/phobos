FROM maven:3.9.16-eclipse-temurin-17@sha256:0af1de9f9b587b9f57a97379c292dc1c1d3ff61a476fdfa1b5eb42ff5b3cbc0f

RUN apt-get update && apt-get install -y \
    bubblewrap \
    python3 \
    tree \
  && rm -rf /var/lib/apt/lists/*

RUN useradd sandboxuser

RUN chown -R sandboxuser:sandboxuser /var/tmp

RUN mkdir -p /home/sandboxuser/.gradle/wrapper/dists \
            /home/sandboxuser/.m2/repository  \
 && chown -R sandboxuser:sandboxuser /home/sandboxuser


USER sandboxuser

# ---------- 4. default entrypoint = pruning script --------------------------
# The compose file appends the language argument (java / python / c).
ENTRYPOINT ["/var/tmp/pruning/run_minimal_fs_all.sh"]
