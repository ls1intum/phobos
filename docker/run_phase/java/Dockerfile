FROM ls1tum/artemis-maven-template:java17-25@sha256:521f4dd3f3c6d81f403e84f2e2af3c459cd42dfd0345886aac1d1032527b07f8


RUN apt-get update && apt-get install -y --no-install-recommends \
    bubblewrap \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

ENV PHOBOS_HOME=/var/tmp/opt/core
RUN mkdir -p "${PHOBOS_HOME}"
COPY *.sh                ${PHOBOS_HOME}/
COPY netblocker.c                 ${PHOBOS_HOME}/
COPY config/BaseLanguage-java.cfg                     ${PHOBOS_HOME}/
COPY config/TailPhobos.cfg                     ${PHOBOS_HOME}/
COPY allowedList.cfg                  ${PHOBOS_HOME}/
RUN gcc -fPIC -shared -o ${PHOBOS_HOME}/libnetblocker.so ${PHOBOS_HOME}/netblocker.c
RUN chmod +x ${PHOBOS_HOME}/*.sh ${PHOBOS_HOME}/*.cfg \
 && chmod +w ${PHOBOS_HOME}/allowedList.cfg && ln -sf phobos.sh ${PHOBOS_HOME}/phobos
ENV PATH=${PHOBOS_HOME}:$PATH