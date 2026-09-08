FROM ls1tum/artemis-maven-template:java17-25


RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

ENV PHOBOS_HOME=/var/tmp/opt/core
RUN mkdir -p "${PHOBOS_HOME}"
COPY *.sh                ${PHOBOS_HOME}/
COPY netblocker.c                 ${PHOBOS_HOME}/
COPY phobos-landlock.c            ${PHOBOS_HOME}/
COPY config/BaseLanguage-java.cfg                     ${PHOBOS_HOME}/
COPY config/TailPhobos.cfg                     ${PHOBOS_HOME}/
COPY allowedList.cfg                  ${PHOBOS_HOME}/
# -O2 is what switches on _FORTIFY_SOURCE: without any optimisation level it is
# off entirely, and this library sits on every connection a submission makes.
# -Wl,-z,now completes RELRO, so the relocation table is read-only once loaded.
RUN gcc -O2 -Wall -Wextra -fPIC -shared -Wl,-z,now \
    -o ${PHOBOS_HOME}/libnetblocker.so ${PHOBOS_HOME}/netblocker.c
# -static-pie rather than -static: plain -static overrides the -fPIE default and
# produces a fixed-address executable, so the binary that applies the sandbox
# would be the one part of the image without address randomisation.
RUN gcc -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o ${PHOBOS_HOME}/phobos-landlock ${PHOBOS_HOME}/phobos-landlock.c
RUN chmod +x ${PHOBOS_HOME}/*.sh ${PHOBOS_HOME}/*.cfg \
 && chmod +w ${PHOBOS_HOME}/allowedList.cfg && ln -sf phobos.sh ${PHOBOS_HOME}/phobos
ENV PATH=${PHOBOS_HOME}:$PATH