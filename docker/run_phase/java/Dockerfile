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
RUN gcc -fPIC -shared -o ${PHOBOS_HOME}/libnetblocker.so ${PHOBOS_HOME}/netblocker.c
RUN gcc -O2 -Wall -Wextra -static -o ${PHOBOS_HOME}/phobos-landlock ${PHOBOS_HOME}/phobos-landlock.c
RUN chmod +x ${PHOBOS_HOME}/*.sh ${PHOBOS_HOME}/*.cfg \
 && chmod +w ${PHOBOS_HOME}/allowedList.cfg && ln -sf phobos.sh ${PHOBOS_HOME}/phobos
ENV PATH=${PHOBOS_HOME}:$PATH