# The three C programs are compiled in a stage of their own, from the same base image the run
# phase uses, so they are built against the C library they will run with. Only the finished
# binaries are copied on, so their sources stay out of the image a submission runs in. The
# final stage below says why the compiler itself stays.
#
# gcc-14 on top of build-essential: the image ships gcc 13, which knows C23 only under its
# draft name -std=gnu2x. Pinning the language rather than taking whatever the base image
# happens to default to is the point of the flag, so the compiler that knows the real name
# is the one that builds them.
FROM ls1tum/artemis-maven-template:java17-25@sha256:521f4dd3f3c6d81f403e84f2e2af3c459cd42dfd0345886aac1d1032527b07f8 AS enforcers
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-14 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY phobos-landlock-filesystem-and-networksystem*.c           /build/
COPY phobos-landlock-filesystem-and-networksystem*.h           /build/
COPY phobos-seccomp-networksystem*.c      /build/
COPY phobos-seccomp-networksystem*.h      /build/
COPY phobos-seccomp-timeoutsystem.c         /build/
# -static-pie rather than -static: plain -static overrides the -fPIE default and
# produces a fixed-address executable, so the binary that applies the sandbox
# would be the one part of the image without address randomisation.
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o /build/phobos-landlock-filesystem-and-networksystem /build/phobos-landlock-filesystem-and-networksystem*.c
# The connect guard is built the same way and held to the same hardening below.
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o /build/phobos-seccomp-networksystem /build/phobos-seccomp-networksystem*.c
# The timeout's group lock is built the same way and held to the same hardening below.
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o /build/phobos-seccomp-timeoutsystem /build/phobos-seccomp-timeoutsystem.c

# No bubblewrap: the filesystem layer is enforced by Landlock now, which needs no
# privileges, no capabilities and no container flags, so the tool that needed all
# three is gone from the image rather than left installed and unused.
#
# The toolchain stays, although the three programs above are no longer compiled here. Three
# of the acceptance suites compile a C probe inside this image at run time: a raw connect()
# the connect guard still catches at the seccomp boundary, a bind probe and the connect-guard
# probe. They are what makes those suites evidence about the image an exercise actually gets
# rather than about a second image built to test with, so the compiler they need is part of it.
# binutils supplies the readelf the build-time hardening check below runs over the three compiled
# binaries. haproxy is the egress broker: the connect guard hands an allowed connection to it,
# and it enforces the allow-list by the TLS host name the guard cannot see;
# tests/haproxy_broker.sh exercises that path inside this image.
FROM ls1tum/artemis-maven-template:java17-25@sha256:521f4dd3f3c6d81f403e84f2e2af3c459cd42dfd0345886aac1d1032527b07f8

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-14 \
    binutils \
    haproxy \
 && rm -rf /var/lib/apt/lists/*

ENV PHOBOS_HOME=/var/tmp/opt/core
RUN mkdir -p "${PHOBOS_HOME}"
COPY *.sh                ${PHOBOS_HOME}/
COPY --from=enforcers /build/phobos-landlock-filesystem-and-networksystem ${PHOBOS_HOME}/
COPY --from=enforcers /build/phobos-seccomp-networksystem ${PHOBOS_HOME}/
COPY --from=enforcers /build/phobos-seccomp-timeoutsystem ${PHOBOS_HOME}/
COPY config/BaseLanguage-java.cfg                     ${PHOBOS_HOME}/
COPY config/TailPhobos.cfg                     ${PHOBOS_HOME}/
# The hardening is measured, not assumed: a DYN type proves -static-pie kept the
# binary position independent, and a BIND_NOW entry proves RELRO is complete. It is
# measured here, on the copies the image actually ships, rather than in the stage that
# produced them. Written to files rather than piped into grep, because a pipe here would
# need pipefail to report a failing readelf and hadolint rejects one without it.
RUN readelf -h ${PHOBOS_HOME}/phobos-landlock-filesystem-and-networksystem > /tmp/wrapper-header.txt \
 && readelf -d ${PHOBOS_HOME}/phobos-landlock-filesystem-and-networksystem > /tmp/wrapper-dynamic.txt \
 && readelf -h ${PHOBOS_HOME}/phobos-seccomp-networksystem > /tmp/guard-header.txt \
 && readelf -d ${PHOBOS_HOME}/phobos-seccomp-networksystem > /tmp/guard-dynamic.txt \
 && readelf -h ${PHOBOS_HOME}/phobos-seccomp-timeoutsystem > /tmp/lock-header.txt \
 && readelf -d ${PHOBOS_HOME}/phobos-seccomp-timeoutsystem > /tmp/lock-dynamic.txt \
 && grep -q 'Type:[[:space:]]*DYN' /tmp/wrapper-header.txt \
 && grep -q 'BIND_NOW' /tmp/wrapper-dynamic.txt \
 && grep -q 'Type:[[:space:]]*DYN' /tmp/guard-header.txt \
 && grep -q 'BIND_NOW' /tmp/guard-dynamic.txt \
 && grep -q 'Type:[[:space:]]*DYN' /tmp/lock-header.txt \
 && grep -q 'BIND_NOW' /tmp/lock-dynamic.txt \
 && rm -f /tmp/wrapper-header.txt /tmp/wrapper-dynamic.txt /tmp/guard-header.txt /tmp/guard-dynamic.txt /tmp/lock-header.txt /tmp/lock-dynamic.txt
# The six entry points, and not the two files that are only ever sourced: a mode on those
# would say they can be run, which is what the check in test.yml states they cannot.
RUN chmod +x ${PHOBOS_HOME}/phobos.sh ${PHOBOS_HOME}/phobos-policy.sh \
      ${PHOBOS_HOME}/phobos-filesystem.sh ${PHOBOS_HOME}/phobos-network.sh \
      ${PHOBOS_HOME}/phobos-resources.sh ${PHOBOS_HOME}/phobos-timeout.sh \
 && ln -sf phobos.sh ${PHOBOS_HOME}/phobos
ENV PATH=${PHOBOS_HOME}:$PATH
