# syntax=docker/dockerfile:1
#
# Build from source:   docker build -t watermelon-pgp .
# Create the data dir: docker run --rm -it -v watermelon-data:/data watermelon-pgp init
# Run:                 docker run -d -p 127.0.0.1:8080:8080 -v watermelon-data:/data \
#                        -v /srv/sftp:/srv/sftp watermelon-pgp
#
# See docs/deployment.md for TLS, the master key and folder permissions.

FROM rust:1.100-slim-trixie AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin watermelon \
    && cp target/release/watermelon /usr/local/bin/watermelon

FROM debian:trixie-slim AS runtime
# A fixed, unprivileged user: give it read/write access to the job folders you mount.
RUN groupadd --system --gid 10001 watermelon \
    && useradd --system --uid 10001 --gid watermelon --home-dir /data --shell /usr/sbin/nologin watermelon \
    && install -d -o watermelon -g watermelon -m 0700 /data
USER watermelon:watermelon
ENV WATERMELON_DATA_DIR=/data \
    WATERMELON_BIND=0.0.0.0:8080 \
    WATERMELON_LOG_FORMAT=json
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["watermelon"]
CMD ["serve"]

# Release images reuse the binaries built by the release workflow (dist/linux/<arch>/watermelon):
#   docker buildx build --target prebuilt --platform linux/amd64,linux/arm64 .
FROM runtime AS prebuilt
ARG TARGETARCH
COPY dist/linux/${TARGETARCH}/watermelon /usr/local/bin/watermelon

# The default target: built from source.
FROM runtime
COPY --from=build /usr/local/bin/watermelon /usr/local/bin/watermelon
