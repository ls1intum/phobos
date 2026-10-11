# The run-phase image for Python exercises. It is built FROM the official Python image, not from
# Artemis's ls1tum/artemis-python-docker, whose current release is Ubuntu 20.04 with Python 3.8 and
# has neither gcc 14 nor the Landlock headers the four C programs need. An Artemis exercise that is
# graded under Phobos must therefore select this image; the suites in build.yml prove exactly it.
#
# The four C programs are compiled in a stage of their own, from the same base image, so they are
# built against the C library they will run with, exactly as docker/protecter/java/Dockerfile does;
# that file says why each flag is there.
FROM python:3.14-slim-trixie@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS enforcers
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

# The toolchain, binutils and haproxy stay for the reasons docker/protecter/java/Dockerfile gives:
# the suites compile their C probes inside the image they test, readelf checks the hardening below,
# and haproxy is the egress broker. procps and openssl are in the Java image's base and not in the
# slim Python one: the suites look for leftover processes with pgrep and send a ClientHello with
# openssl. pytest is what a Python exercise's tests run with; it and every package it pulls in are
# pinned, so the weekly rebuild cannot change what a pruned base names without a pull request.
FROM python:3.14-slim-trixie@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-14 \
    binutils \
    haproxy \
    openssl \
    procps \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pytest==9.1.1 iniconfig==2.3.1 packaging==26.3 pluggy==1.6.0 Pygments==2.21.0

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
COPY config/BaseLanguage-python.cfg ${PHOBOS_HOME}/
COPY config/TailPhobos.cfg          ${PHOBOS_HOME}/
# The programming language configurations are Phobos's own data, one per configuration name an Ares 2
# policy can give, read only when a run imports such a policy; a run that imports none never reads them.
# Every one there is a Java one, so a Python exercise has nothing to import; they ship here all the same,
# since they belong to Phobos rather than to a language.
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
