# syntax=docker/dockerfile:1
#
# Build from source:   docker build -t watermelon-pgp .
# Create the data dir: docker run --rm -it -v watermelonpgp-data:/data watermelon-pgp init
# Run:                 docker run -d -p 127.0.0.1:8080:8080 -v watermelonpgp-data:/data \
#                        -v /srv/sftp:/srv/sftp watermelon-pgp
#
# See docs/deployment.md for TLS, the master key and folder permissions.

FROM rust:1.100-slim-trixie AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin watermelonpgp \
    && cp target/release/watermelonpgp /usr/local/bin/watermelonpgp

FROM debian:trixie-slim AS runtime
# A fixed, unprivileged user: give it read/write access to the job folders you mount.
RUN groupadd --system --gid 10001 watermelonpgp \
    && useradd --system --uid 10001 --gid watermelonpgp --home-dir /data --shell /usr/sbin/nologin watermelonpgp \
    && install -d -o watermelonpgp -g watermelonpgp -m 0700 /data
USER watermelonpgp:watermelonpgp
ENV WATERMELONPGP_DATA_DIR=/data \
    WATERMELONPGP_BIND=0.0.0.0:8080 \
    WATERMELONPGP_LOG_FORMAT=json
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["watermelonpgp"]
CMD ["serve"]

# Release images reuse the binaries built by the release workflow (dist/linux/<arch>/watermelonpgp):
#   docker buildx build --target prebuilt --platform linux/amd64,linux/arm64 .
FROM runtime AS prebuilt
ARG TARGETARCH
COPY dist/linux/${TARGETARCH}/watermelonpgp /usr/local/bin/watermelonpgp

# The default target: built from source.
FROM runtime
COPY --from=build /usr/local/bin/watermelonpgp /usr/local/bin/watermelonpgp
