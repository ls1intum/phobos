FROM ls1tum/artemis-maven-template:java17-25


# gcc-14 on top of build-essential: the image ships gcc 13, which knows C23
# only under its draft name -std=gnu2x. Pinning the language rather than taking
# whatever the base image happens to default to is the point of the flag, so the
# compiler that knows the real name is the one that builds both artefacts.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-14 \
 && rm -rf /var/lib/apt/lists/*

ENV PHOBOS_HOME=/var/tmp/opt/core
RUN mkdir -p "${PHOBOS_HOME}"
COPY *.sh                ${PHOBOS_HOME}/
COPY netblocker.c                 ${PHOBOS_HOME}/
COPY phobos-landlock*.c           ${PHOBOS_HOME}/
COPY phobos-landlock*.h           ${PHOBOS_HOME}/
COPY config/BaseLanguage-java.cfg                     ${PHOBOS_HOME}/
COPY config/TailPhobos.cfg                     ${PHOBOS_HOME}/
COPY allowedList.cfg                  ${PHOBOS_HOME}/
# -O2 is what switches on _FORTIFY_SOURCE: without any optimisation level it is
# off entirely, and this library sits on every connection a submission makes.
# -Wl,-z,now completes RELRO, so the relocation table is read-only once loaded.
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -fPIC -shared -Wl,-z,now \
    -o ${PHOBOS_HOME}/libnetblocker.so ${PHOBOS_HOME}/netblocker.c
# -static-pie rather than -static: plain -static overrides the -fPIE default and
# produces a fixed-address executable, so the binary that applies the sandbox
# would be the one part of the image without address randomisation.
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o ${PHOBOS_HOME}/phobos-landlock ${PHOBOS_HOME}/phobos-landlock*.c
# The hardening is measured, not assumed: a DYN type proves -static-pie kept the
# binary position independent, and a BIND_NOW entry proves RELRO is complete.
RUN readelf -h ${PHOBOS_HOME}/phobos-landlock | grep -q 'Type:[[:space:]]*DYN' \
 && readelf -d ${PHOBOS_HOME}/phobos-landlock | grep -q 'BIND_NOW' \
 && readelf -d ${PHOBOS_HOME}/libnetblocker.so | grep -q 'BIND_NOW'
RUN chmod +x ${PHOBOS_HOME}/*.sh ${PHOBOS_HOME}/*.cfg \
 && chmod +w ${PHOBOS_HOME}/allowedList.cfg && ln -sf phobos.sh ${PHOBOS_HOME}/phobos
ENV PATH=${PHOBOS_HOME}:$PATH