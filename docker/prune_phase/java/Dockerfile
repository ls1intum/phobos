FROM maven:3.10.0-eclipse-temurin-17@sha256:c8e807dc64124be4152eff679fe8abebcf3b281658b69f1cb096cd2dac3d5699

# bubblewrap is what the discovery phase measures with: it hides a directory behind an
# empty tmpfs, which is the one thing Landlock cannot do and the reason this phase does not
# use the run phase's mechanism. python3 runs the artefact helpers.
RUN apt-get update && apt-get install -y \
    bubblewrap \
    python3 \
  && rm -rf /var/lib/apt/lists/*

RUN useradd sandboxuser

RUN mkdir -p /home/sandboxuser/.gradle/wrapper/dists \
            /home/sandboxuser/.m2/repository  \
 && chown -R sandboxuser:sandboxuser /home/sandboxuser


USER sandboxuser

# The entry point is the pruning script; the compose file appends the language
# argument (java or python).
ENTRYPOINT ["/var/tmp/pruning/run_minimal_fs_all.sh"]
