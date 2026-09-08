FROM maven:3.9.16-eclipse-temurin-17

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
