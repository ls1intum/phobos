# The run-phase image for Swift exercises that Artemis builds with its Swift template: a Swift package for the
# solution and a Swift package of XCTest tests, built with `swift build` and run with `swift test`. It is built FROM the
# official Swift image of the release Artemis's own Swift image names (swift:6.2-noble, Ubuntu 24.04) and holds the
# three packages the test package depends on, so that nothing is fetched at prune time or at grading time. An Artemis
# exercise that is graded under Phobos must therefore select this image; the suites in build.yml prove exactly it.
#
# The four C programs are compiled in a stage of their own, from a Debian image, so they are built against a C library
# and linked static-pie, which is what makes the same binaries run on the Ubuntu image below. docker/protecter/java/Dockerfile
# says why each flag is there.
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


# The three packages the test package of the template resolves from GitHub, each cloned at the commit that the
# resolution of its versions gave (HTMLString 5.0.0, swift-ast 0.19.10, swift-junit 2.1.0). Git holds each clone to
# its commit by the commit's hash, and the clone keeps no tag but the version it was cloned for, so that the
# resolution of a range such as `from: "2.0.0"` can only find that version. SwiftPM is pointed at the clones by the mirror file next to them, so that the
# resolution of `from: "2.0.0"` and the like finds the versions as tags and reaches no network.
FROM swift:6.2-noble@sha256:eccc7a97f9b9881d9659e2e788081fd7675f86d39793b51200bfb178398b3784 AS swiftdeps
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN git clone --quiet https://github.com/alexaubry/HTMLString.git /opt/swift-deps/HTMLString \
 && git -C /opt/swift-deps/HTMLString checkout --quiet --detach 373048cc4084dd7481c86e3bee41612eff93b14d \
 && git clone --quiet https://github.com/yanagiba/swift-ast.git /opt/swift-deps/swift-ast \
 && git -C /opt/swift-deps/swift-ast checkout --quiet --detach 497339ef32653774563edd0694cc0befeafee4ae \
 && git clone --quiet https://github.com/allegro/swift-junit.git /opt/swift-deps/swift-junit \
 && git -C /opt/swift-deps/swift-junit checkout --quiet --detach f093c446dd280ec726e8102effd9662bb0f5465b \
 && for repository in HTMLString:5.0.0 swift-ast:v0.19.10 swift-junit:2.1.0; do \
      git -C "/opt/swift-deps/${repository%%:*}" tag -l | xargs git -C "/opt/swift-deps/${repository%%:*}" tag -d >/dev/null \
      && git -C "/opt/swift-deps/${repository%%:*}" for-each-ref --format='%(refname)' refs/remotes refs/heads \
        | xargs -r -n1 git -C "/opt/swift-deps/${repository%%:*}" update-ref -d \
      && git -C "/opt/swift-deps/${repository%%:*}" tag "${repository##*:}" \
      || exit 1; \
    done
COPY pin/swift-mirrors.json /opt/swift-deps/mirrors.json

# The toolchain, binutils and haproxy stay for the reasons docker/protecter/java/Dockerfile gives: the suites compile
# their C probes inside the image they test, readelf checks the hardening below, and haproxy is the egress broker.
# procps and openssl are what the suites look for leftover processes and send a ClientHello with, and python3 is what
# the network probes are written in. The Swift toolchain is the one the base image brings.
FROM swift:6.2-noble@sha256:eccc7a97f9b9881d9659e2e788081fd7675f86d39793b51200bfb178398b3784

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-14 \
    binutils \
    haproxy \
    openssl \
    procps \
    python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=swiftdeps /opt/swift-deps /opt/swift-deps

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
COPY config/BaseLanguage-swift.cfg ${PHOBOS_HOME}/
COPY config/TailPhobos.cfg          ${PHOBOS_HOME}/
# The programming language configurations are Phobos's own data, one per configuration name an Ares 2
# policy can give, read only when a run imports such a policy; a run that imports none never reads them.
# Every one there is a Java one, so a Swift exercise has nothing to import, but the language-neutral
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
