# The image every graded run happens in is Artemis's default Java image, java25-1: JDK 25, Maven 3.9.16 and
# Gradle 9.8.0 pre-seeded, the image the Java test template's release 25 compiles in. Pinned by the digest of
# its multi-architecture index, never by that of one platform, so the same line holds on amd64 and arm64
# (looked up with `docker buildx imagetools inspect`). A graded exercise whose wrapper names a Gradle before
# 9.1.0 cannot run on it at all.
#
# Two stages below pre-load the dependencies the two reference exercises resolve, from those exercises' own
# online builds, and hold what each build added or changed to a committed manifest. They exist so that a
# prune and a grading run read the same bytes: a policy that names a file under /root/.m2 or /root/.gradle
# by path is only right for an image holding exactly that file, since another version would be refused with
# EACCES and a missing one would leave the policy naming a path that does not exist. The prune image is built
# FROM this image and adds nothing under either directory, so it holds the same files. "The same" means the
# same content: Maven's _remote.repositories files differ in a time stamp comment, and of Gradle's
# caches/modules-2 only the artefact store files-2.1 is pinned, while the metadata beside it, which Gradle
# needs to resolve offline, is carried on as the build left it.
#
# The four C programs are compiled in a stage of their own, from the same base image the run
# phase uses, so they are built against the C library they will run with. Only the finished
# binaries are copied on, so their sources stay out of the image a submission runs in. The
# final stage below says why the compiler itself stays. Their source folders keep the layout of
# the repository, because the report-only supervisor links the enforcer's model and the connect
# guard's handoff module and includes their headers by paths relative to its own folder.
#
# gcc-14 on top of build-essential: the image ships gcc 13, which knows C23 only under its
# draft name -std=gnu2x. Pinning the language rather than taking whatever the base image
# happens to default to is the point of the flag, so the compiler that knows the real name
# is the one that builds them.
FROM ls1tum/artemis-maven-template:java25-1@sha256:b8393cc0fd728e1645e63380e8470443a691cedf5aaa7b1b86fd33250141de3b AS enforcers
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-14 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY phobos-landlock-filesystem-and-networksystem /build/phobos-landlock-filesystem-and-networksystem
COPY phobos-seccomp-networksystem                 /build/phobos-seccomp-networksystem
COPY phobos-seccomp-filesystem                    /build/phobos-seccomp-filesystem
COPY phobos-seccomp-timeoutsystem                 /build/phobos-seccomp-timeoutsystem
# -static-pie rather than -static: plain -static overrides the -fPIE default and
# produces a fixed-address executable, so the binary that applies the sandbox
# would be the one part of the image without address randomisation.
RUN mkdir -p /build/bin \
 && gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o /build/bin/phobos-landlock-filesystem-and-networksystem \
    /build/phobos-landlock-filesystem-and-networksystem/*.c
# The connect guard is built the same way and held to the same hardening below.
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o /build/bin/phobos-seccomp-networksystem /build/phobos-seccomp-networksystem/*.c
# The timeout's group lock is built the same way and held to the same hardening below.
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o /build/bin/phobos-seccomp-timeoutsystem \
    /build/phobos-seccomp-timeoutsystem/phobos-seccomp-timeoutsystem.c
# The report-only supervisor is built the same way and held to the same hardening below. It
# carries the enforcer's diagnostics-free model and the connect guard's handoff module, never the
# enforcer's or the guard's own diagnostics.
RUN gcc-14 -std=gnu23 -O2 -Wall -Wextra -static-pie -Wl,-z,now \
    -o /build/bin/phobos-seccomp-filesystem /build/phobos-seccomp-filesystem/*.c \
    /build/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-policy.c \
    /build/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-path-rule.c \
    /build/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-model.c \
    /build/phobos-seccomp-networksystem/phobos-seccomp-networksystem-handoff.c

# The dependencies of the Maven reference exercise, pre-loaded from its own online build, which Artemis's
# `mvn clean test` is, plus --strict-checksums. pin-repository.sh records what the build added or changed under
# the local repository and refuses the image unless that set is exactly the manifest's and every file is as the
# manifest says. The exercise's sources stay in this discarded stage; only the repository enters the grading image.
# The result is the equality of that set with the manifest, not the build's exit status: a build that ran no
# test resolves no test engine, and its manifest would not match.
FROM ls1tum/artemis-maven-template:java25-1@sha256:b8393cc0fd728e1645e63380e8470443a691cedf5aaa7b1b86fd33250141de3b AS maven-repository
COPY pin/pin-repository.sh /usr/local/bin/pin-repository.sh
COPY pin/maven-repository.sha256 /maven-repository.sha256
COPY exercises/java-maven/maven-reference /var/tmp/testing-dir
WORKDIR /var/tmp/testing-dir
RUN pin-repository.sh verify /root/.m2/repository /maven-repository.sha256 mvn --batch-mode --strict-checksums clean test

# The same for the Gradle reference exercise. Gradle resolves offline from its metadata cache as well as from the
# artefact store, so the whole of caches/modules-2 is carried on, while the manifest pins the artefact store,
# files-2.1, whose paths name the SHA-1 of their content. The metadata is an index the build rewrites each run.
FROM ls1tum/artemis-maven-template:java25-1@sha256:b8393cc0fd728e1645e63380e8470443a691cedf5aaa7b1b86fd33250141de3b AS gradle-repository
COPY pin/pin-repository.sh /usr/local/bin/pin-repository.sh
COPY pin/gradle-repository.sha256 /gradle-repository.sha256
COPY exercises/java/gradle-reference /var/tmp/testing-dir
WORKDIR /var/tmp/testing-dir
# The wrapper jar runs as root here, so it is held to the checksum Gradle publishes for 9.8.0
# (services.gradle.org/distributions/gradle-9.8.0-wrapper.jar.sha256); the distribution it then fetches is held to
# distributionSha256Sum in gradle-wrapper.properties.
RUN printf '%s  %s\n' 238e777fcddd7e34f9708186085def2abd6e08e658505b38718d79d74c21abd5 gradle/wrapper/gradle-wrapper.jar > /wrapper.sha256 \
 && sha256sum --strict -c /wrapper.sha256 \
 && pin-repository.sh verify /root/.gradle/caches/modules-2/files-2.1 /gradle-repository.sha256 ./gradlew clean test

# No bubblewrap: the filesystem layer is enforced by Landlock now, which needs no
# privileges, no capabilities and no container flags, so the tool that needed all
# three is gone from the image rather than left installed and unused.
#
# The toolchain stays, although the four programs above are no longer compiled here. Three
# of the acceptance suites compile a C probe inside this image at run time: a raw connect()
# the connect guard still catches at the seccomp boundary, a bind probe and the connect-guard
# probe. They are what makes those suites evidence about the image an exercise actually gets
# rather than about a second image built to test with, so the compiler they need is part of it.
# binutils supplies the readelf the build-time hardening check below runs over the four compiled
# binaries. haproxy is the egress broker: the connect guard hands an allowed connection to it,
# and it enforces the allow-list by the TLS host name the guard cannot see;
# tests/integration/haproxy_broker.sh exercises that path inside this image.
FROM ls1tum/artemis-maven-template:java25-1@sha256:b8393cc0fd728e1645e63380e8470443a691cedf5aaa7b1b86fd33250141de3b

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-14 \
    binutils \
    haproxy \
 && rm -rf /var/lib/apt/lists/*

ENV PHOBOS_HOME=/var/tmp/opt/core
RUN mkdir -p "${PHOBOS_HOME}"
COPY *.sh                ${PHOBOS_HOME}/
# The shared and per-subsystem helpers keep their folders, which the layer scripts source by
# name, so the image mirrors the repository layout rather than flattening them.
COPY phobos-tools-common        ${PHOBOS_HOME}/phobos-tools-common
COPY phobos-tools-policysystem  ${PHOBOS_HOME}/phobos-tools-policysystem
COPY phobos-tools-filesystem    ${PHOBOS_HOME}/phobos-tools-filesystem
COPY phobos-tools-networksystem ${PHOBOS_HOME}/phobos-tools-networksystem
COPY --from=enforcers /build/bin/phobos-landlock-filesystem-and-networksystem ${PHOBOS_HOME}/
COPY --from=enforcers /build/bin/phobos-seccomp-networksystem ${PHOBOS_HOME}/
COPY --from=enforcers /build/bin/phobos-seccomp-timeoutsystem ${PHOBOS_HOME}/
COPY --from=enforcers /build/bin/phobos-seccomp-filesystem ${PHOBOS_HOME}/
COPY config/BaseLanguage-java.cfg                     ${PHOBOS_HOME}/
COPY config/TailPhobos.cfg                     ${PHOBOS_HOME}/
# The pre-loaded dependency repositories of the two stages above, over the base image's own.
COPY --from=maven-repository /root/.m2/repository /root/.m2/repository
COPY --from=gradle-repository /root/.gradle/caches/modules-2 /root/.gradle/caches/modules-2
# The programming language configurations, one per configuration name an Ares 2 policy can give.
# They sit in a folder of their own beside the base policies, which the Base*.cfg glob every run
# folds does not reach, so a run that imports no Ares policy never reads them.
COPY config/language-configurations ${PHOBOS_HOME}/language-configurations
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
# The six entry points, and not the helpers under phobos-tools-*, which are only ever sourced: a
# mode on those would say they can be run, which is what the check in test.yml states they cannot.
RUN chmod +x ${PHOBOS_HOME}/phobos.sh ${PHOBOS_HOME}/phobos-policysystem.sh \
      ${PHOBOS_HOME}/phobos-filesystem.sh ${PHOBOS_HOME}/phobos-networksystem.sh \
      ${PHOBOS_HOME}/phobos-resourcesystem.sh ${PHOBOS_HOME}/phobos-timeoutsystem.sh \
 && ln -sf phobos.sh ${PHOBOS_HOME}/phobos
ENV PATH=${PHOBOS_HOME}:$PATH
