FROM busybox:uclibc@sha256:297dda192bda2157ddf40abb47a45a1090caff1864db9cfb9ce4b901ba318a3c AS src

FROM scratch
COPY --from=src /bin/true /bin/true
ENTRYPOINT ["/bin/true"]
