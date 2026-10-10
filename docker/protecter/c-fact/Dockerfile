# The run-phase image for C exercises that Artemis builds with its FACT template: a Makefile, gcc, and FACT, a
# Python package that compiles the program, parses it with libclang and runs the tests of exercise.yml. It is built
# FROM the official Debian image, not from Artemis's ls1tum/artemis-fact-minimal-docker, whose current release is
# Debian 12 with gcc 12 and has neither gcc 14 nor the Landlock headers the four C programs need. An Artemis
# exercise that is graded under Phobos must therefore select this image; the suites in build.yml prove exactly it.
#
# FACT is taken from the commit of that Artemis image that Artemis names as release 1.1.0, as a source archive held
# to its SHA-256, and installed with the versions that release carries (protecter/image/fact-requirements.txt),
# beside libclang 19, the oldest libclang Debian 13 ships, for the clang bindings 14.0 that FACT pins. Nothing is fetched at
# prune time or at grading time.
#
# The four C programs are compiled in a stage of their own, from the same base image, so they are
# built against the C library they will run with, exactly as docker/protecter/java/Dockerfile does;
# that file says why each flag is there.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS enforcers
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-14 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY phobos-landlock-filesystem-and-networksystem /build/phobos-landlock-filesystem-and-networksystem
COPY phobos-seccomp-networksystem                 /build/phobos-seccomp-networksystem
COPY phobos-seccomp-filesystem                    /build/phobos-seccomp-filesystem
COPY phobos-seccomp-timeoutsystem                 /build/phobos-seccomp-timeoutsystem
RUN mkdir -p /build/bin \
 && gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o /build/bin/phobos-landlock-filesystem-and-networksystem \
    /build/phobos-landlock-filesystem-and-networksystem/*.c
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o /build/bin/phobos-seccomp-networksystem /build/phobos-seccomp-networksystem/*.c \
    /build/phobos-seccomp-filesystem/phobos-seccomp-filesystem-*.c \
    /build/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-policy.c \
    /build/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-path-rule.c \
    /build/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-model.c
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o /build/bin/phobos-seccomp-timeoutsystem \
    /build/phobos-seccomp-timeoutsystem/phobos-seccomp-timeoutsystem.c
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o /build/bin/phobos-seccomp-filesystem /build/phobos-seccomp-filesystem/*.c \
    /build/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-policy.c \
    /build/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-path-rule.c \
    /build/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-model.c \
    /build/phobos-seccomp-networksystem/phobos-seccomp-networksystem-handoff.c

# FACT and its Python packages, installed into /opt/python in a stage of their own, so that the image the suites test
# holds no pip and no archive.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS fact
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    python3 \
    python3-pip \
 && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:27eebb2ae2a8a4ae1aee06f1f2817ec6511d23c458d7a0f8b700bb93454c434a \
    https://github.com/ls1intum/artemis-fact-minimal-docker/archive/b596492ca7429d7645038be0bc72b0e6f3e6fb0c.tar.gz /tmp/fact-source.tar.gz
COPY pin/fact-requirements.txt /tmp/fact-requirements.txt
RUN mkdir /tmp/fact-source \
 && tar -xzf /tmp/fact-source.tar.gz --strip-components=1 -C /tmp/fact-source \
 && python3 -m pip install --no-cache-dir --break-system-packages --target /opt/python -r /tmp/fact-requirements.txt \
 && python3 -m pip install --no-cache-dir --break-system-packages --no-deps --target /opt/python /tmp/fact-source

# The toolchain, binutils and haproxy stay for the reasons docker/protecter/java/Dockerfile gives: the suites compile
# their C probes inside the image they test, readelf checks the hardening below, and haproxy is the egress broker.
# make and python3 are what FACT runs with, libclang what it parses with; procps and openssl are what the suites look
# for leftover processes and send a ClientHello with.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-14 \
    binutils \
    haproxy \
    libclang-common-19-dev \
    libclang1-19 \
    make \
    openssl \
    procps \
    python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=fact /opt/python /opt/python
ENV PYTHONPATH=/opt/python

ENV PHOBOS_HOME=/var/tmp/opt/core
RUN mkdir -p "${PHOBOS_HOME}"
COPY *.sh                ${PHOBOS_HOME}/
COPY phobos-tools-common        ${PHOBOS_HOME}/phobos-tools-common
COPY phobos-tools-policysystem  ${PHOBOS_HOME}/phobos-tools-policysystem
COPY phobos-tools-filesystem    ${PHOBOS_HOME}/phobos-tools-filesystem
COPY phobos-tools-networksystem ${PHOBOS_HOME}/phobos-tools-networksystem
COPY --from=enforcers /build/bin/phobos-landlock-filesystem-and-networksystem ${PHOBOS_HOME}/
COPY --from=enforcers /build/bin/phobos-seccomp-networksystem ${PHOBOS_HOME}/
COPY --from=enforcers /build/bin/phobos-seccomp-timeoutsystem ${PHOBOS_HOME}/
COPY --from=enforcers /build/bin/phobos-seccomp-filesystem ${PHOBOS_HOME}/
COPY config/BaseLanguage-c-fact.cfg ${PHOBOS_HOME}/
COPY config/TailPhobos.cfg          ${PHOBOS_HOME}/
# The programming language configurations are Phobos's own data, one per configuration name an Ares 2
# policy can give, read only when a run imports such a policy; a run that imports none never reads them.
# Every one there is a Java one, so a C exercise has nothing to import, but the language-neutral
# suites this image is held to import them to prove the import and they need the files beside the scripts.
COPY config/language-configurations ${PHOBOS_HOME}/language-configurations
RUN readelf -h ${PHOBOS_HOME}/phobos-landlock-filesystem-and-networksystem > /tmp/wrapper-header.txt \
 && readelf -d ${PHOBOS_HOME}/phobos-landlock-filesystem-and-networksystem > /tmp/wrapper-dynamic.txt \
 && readelf -h ${PHOBOS_HOME}/phobos-seccomp-networksystem > /tmp/guard-header.txt \
 && readelf -d ${PHOBOS_HOME}/phobos-seccomp-networksystem > /tmp/guard-dynamic.txt \
 && readelf -h ${PHOBOS_HOME}/phobos-seccomp-timeoutsystem > /tmp/lock-header.txt \
 && readelf -d ${PHOBOS_HOME}/phobos-seccomp-timeoutsystem > /tmp/lock-dynamic.txt \
 && readelf -h ${PHOBOS_HOME}/phobos-seccomp-filesystem > /tmp/reporter-header.txt \
 && readelf -d ${PHOBOS_HOME}/phobos-seccomp-filesystem > /tmp/reporter-dynamic.txt \
 && grep -q 'Type:[[:space:]]*DYN' /tmp/wrapper-header.txt \
 && grep -q 'BIND_NOW' /tmp/wrapper-dynamic.txt \
 && grep -q 'Type:[[:space:]]*DYN' /tmp/guard-header.txt \
 && grep -q 'BIND_NOW' /tmp/guard-dynamic.txt \
 && grep -q 'Type:[[:space:]]*DYN' /tmp/lock-header.txt \
 && grep -q 'BIND_NOW' /tmp/lock-dynamic.txt \
 && grep -q 'Type:[[:space:]]*DYN' /tmp/reporter-header.txt \
 && grep -q 'BIND_NOW' /tmp/reporter-dynamic.txt \
 && rm -f /tmp/wrapper-header.txt /tmp/wrapper-dynamic.txt /tmp/guard-header.txt /tmp/guard-dynamic.txt /tmp/lock-header.txt /tmp/lock-dynamic.txt /tmp/reporter-header.txt /tmp/reporter-dynamic.txt
RUN chmod +x ${PHOBOS_HOME}/phobos.sh ${PHOBOS_HOME}/phobos-policysystem.sh \
      ${PHOBOS_HOME}/phobos-filesystem.sh ${PHOBOS_HOME}/phobos-networksystem.sh \
      ${PHOBOS_HOME}/phobos-resourcesystem.sh ${PHOBOS_HOME}/phobos-timeoutsystem.sh \
      ${PHOBOS_HOME}/phobos-cli.sh \
 && ln -sf phobos.sh ${PHOBOS_HOME}/phobos
ENV PATH=${PHOBOS_HOME}:$PATH
