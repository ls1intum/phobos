FROM maven:3.10.0-eclipse-temurin-17@sha256:39410d47e240f9177259242e63bf78232808ed77968ebf7e3957b0fa4656f31d

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
