# syntax=docker/dockerfile:1.7
#
# Builds UwUSpamNet from source:
#
#   docker build -f docker/Dockerfile -t uwuspamnet .
#
# CI uses docker/Dockerfile.release instead, with binaries it cross-compiled before (no QEMU for
# arm64). Both end in the same image.

FROM rust:1-slim-trixie AS build
WORKDIR /src
COPY . .
# The cached target directory can hold an earlier build whose sources look unchanged to cargo,
# so the service's own sources are touched first.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    touch src/main.rs src/lib.rs \
 && cargo build --release --locked \
 && cp target/release/uwuspamnet /usr/local/bin/uwuspamnet

# Debian has the tools distroless lacks: make /data, owned by the user the service runs as.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS prep
COPY --from=build /usr/local/bin/uwuspamnet /usr/local/bin/uwuspamnet
RUN chmod 755 /usr/local/bin/uwuspamnet && install -d -o 10001 -g 10001 /data

# Distroless (glibc, no shell), pinned by digest; cc-debian13 is trixie, like the build.
FROM gcr.io/distroless/cc-debian13@sha256:e1f5543d45a2cd7c02a5b43dda5f0ff30729b4832113759d01ed39b0b152cddb
COPY --from=prep /usr/local/bin/ /usr/local/bin/
COPY --from=prep --chown=10001:10001 /data /data
USER 10001:10001
ENV SPAMNET_DATA=/data \
    SPAMNET_LISTEN=0.0.0.0:8080 \
    HOME=/data
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --start-interval=2s --retries=3 \
    CMD ["/usr/local/bin/uwuspamnet", "health"]
ENTRYPOINT ["/usr/local/bin/uwuspamnet"]
CMD ["serve"]
