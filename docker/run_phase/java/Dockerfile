# libnetblocker.so is built in a stage of its own, on the toolchain netblocker-build.sh
# pins, and copied into the image; it is not committed anywhere. The stage's C library is
# newer than the image's; CI refuses a library that needs a newer one than the 2.39 the
# image below ships.
FROM ubuntu:26.04@sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78 AS netblocker
COPY build/netblocker-build.sh /tmp/netblocker/netblocker-build.sh
COPY netblocker/ /tmp/netblocker/source/
RUN /tmp/netblocker/netblocker-build.sh install \
 && /tmp/netblocker/netblocker-build.sh build /tmp/netblocker/source /tmp/netblocker/libnetblocker.so

FROM ls1tum/artemis-maven-template:java17-25@sha256:521f4dd3f3c6d81f403e84f2e2af3c459cd42dfd0345886aac1d1032527b07f8


# No bubblewrap: the filesystem layer is enforced by Landlock now, which needs no
# privileges, no capabilities and no container flags, so the tool that needed all
# three is gone from the image rather than left installed and unused.
#
# gcc-14 on top of build-essential: the image ships gcc 13, which knows C23 only
# under its draft name -std=gnu2x. Pinning the language rather than taking
# whatever the base image happens to default to is the point of the flag, so the
# compiler that knows the real name is the one that builds the wrapper.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-14 \
 && rm -rf /var/lib/apt/lists/*

ENV PHOBOS_HOME=/var/tmp/opt/core
RUN mkdir -p "${PHOBOS_HOME}"
COPY *.sh                ${PHOBOS_HOME}/
COPY --from=netblocker /tmp/netblocker/libnetblocker.so ${PHOBOS_HOME}/
COPY phobos-landlock*.c           ${PHOBOS_HOME}/
COPY phobos-landlock*.h           ${PHOBOS_HOME}/
COPY phobos-connect-guard*.c      ${PHOBOS_HOME}/
COPY phobos-connect-guard*.h      ${PHOBOS_HOME}/
COPY config/BaseLanguage-java.cfg                     ${PHOBOS_HOME}/
COPY config/TailPhobos.cfg                     ${PHOBOS_HOME}/
# -static-pie rather than -static: plain -static overrides the -fPIE default and
# produces a fixed-address executable, so the binary that applies the sandbox
# would be the one part of the image without address randomisation.
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o ${PHOBOS_HOME}/phobos-landlock ${PHOBOS_HOME}/phobos-landlock*.c
# The connect guard is built the same way and held to the same hardening below.
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o ${PHOBOS_HOME}/phobos-connect-guard ${PHOBOS_HOME}/phobos-connect-guard*.c
# The hardening is measured, not assumed: a DYN type proves -static-pie kept the
# binary position independent, and a BIND_NOW entry proves RELRO is complete.
# Written to files rather than piped into grep, because a pipe here would need
# pipefail to report a failing readelf and hadolint rejects one without it.
RUN readelf -h ${PHOBOS_HOME}/phobos-landlock > /tmp/wrapper-header.txt \
 && readelf -d ${PHOBOS_HOME}/phobos-landlock > /tmp/wrapper-dynamic.txt \
 && readelf -h ${PHOBOS_HOME}/phobos-connect-guard > /tmp/guard-header.txt \
 && readelf -d ${PHOBOS_HOME}/phobos-connect-guard > /tmp/guard-dynamic.txt \
 && readelf -d ${PHOBOS_HOME}/libnetblocker.so > /tmp/library-dynamic.txt \
 && grep -q 'Type:[[:space:]]*DYN' /tmp/wrapper-header.txt \
 && grep -q 'BIND_NOW' /tmp/wrapper-dynamic.txt \
 && grep -q 'Type:[[:space:]]*DYN' /tmp/guard-header.txt \
 && grep -q 'BIND_NOW' /tmp/guard-dynamic.txt \
 && grep -q 'BIND_NOW' /tmp/library-dynamic.txt \
 && rm -f /tmp/wrapper-header.txt /tmp/wrapper-dynamic.txt /tmp/guard-header.txt /tmp/guard-dynamic.txt /tmp/library-dynamic.txt
RUN chmod +x ${PHOBOS_HOME}/*.sh ${PHOBOS_HOME}/*.cfg \
 && ln -sf phobos.sh ${PHOBOS_HOME}/phobos
ENV PATH=${PHOBOS_HOME}:$PATH
