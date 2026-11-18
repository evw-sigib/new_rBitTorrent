# syntax=docker/dockerfile:1.7
#
# rbittorrent: rtbit + a Rust PID-1 supervisor that owns WireGuard,
# nftables and NAT-PMP. No shell scripts, no s6, no wg-quick.
#
# Build (CI does this per arch with buildx):
#   docker buildx build --platform linux/arm64 --build-arg BUILD_ARCH=aarch64 .

ARG ALPINE_VERSION=3.24
ARG RUST_VERSION=1.99

# Upstream rustTorrent release, pinned by digest (multi-arch index:
# linux/amd64 + linux/arm64). The image ships a static musl /bin/rtbit.
ARG RTBIT_IMAGE=ghcr.io/thedancingdeveloper-org/rusttorrent:v0.2.0-beta.4@sha256:839e6dac7e6d591364a14e99d51905e8333db5d4fab6242c1ec27cbf8f36039a

# ---------------------------------------------------------------------------
FROM ${RTBIT_IMAGE} AS rtbit

# ---------------------------------------------------------------------------
# The supervisor is built natively for the target platform: the mimalloc
# global allocator is C code, and the Rust Alpine image already carries a
# native gcc + musl-dev. Static musl, opt-level 3, fat LTO, one codegen unit,
# stripped (see supervisor/Cargo.toml).
FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS supervisor
ARG TARGETARCH
WORKDIR /src
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
COPY supervisor/Cargo.toml supervisor/Cargo.lock supervisor/clippy.toml ./
COPY supervisor/src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,id=supervisor-${TARGETARCH},sharing=locked \
    cargo build --release --locked \
 && install -D -m 0755 target/release/rbittorrent-supervisor /out/rbittorrent-supervisor

# ---------------------------------------------------------------------------
FROM alpine:${ALPINE_VERSION}

ARG BUILD_ARCH=amd64
ARG BUILD_VERSION=1.0.0
ARG BUILD_REPOSITORY=evw-sigib/new_rbittorrent

# iproute2-minimal: full netlink `ip` (BusyBox ip cannot create WireGuard
# links). wireguard-tools-wg: only the `wg` binary, no wg-quick.
RUN apk add --no-cache \
      ca-certificates \
      iproute2-minimal \
      nftables \
      wireguard-tools-wg \
      tzdata \
 && rm -rf /var/cache/apk/* /usr/share/man /usr/share/doc

COPY --from=rtbit /bin/rtbit /usr/local/bin/rtbit
COPY --from=supervisor /out/rbittorrent-supervisor /usr/local/bin/rbittorrent-supervisor

ENV RUST_BACKTRACE=0

LABEL \
    io.hass.name="rBittorrent" \
    io.hass.description="rtbit behind a fail-closed Proton VPN WireGuard kill-switch with NAT-PMP" \
    io.hass.type="app" \
    io.hass.version="${BUILD_VERSION}" \
    io.hass.arch="${BUILD_ARCH}" \
    org.opencontainers.image.title="rbittorrent" \
    org.opencontainers.image.description="rtbit behind a fail-closed WireGuard kill-switch for Home Assistant" \
    org.opencontainers.image.version="${BUILD_VERSION}" \
    org.opencontainers.image.source="https://github.com/${BUILD_REPOSITORY}" \
    org.opencontainers.image.licenses="Apache-2.0"

HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
    CMD ["/usr/local/bin/rbittorrent-supervisor", "healthcheck"]

# PID 1 (config.yaml `init: false`): signals, zombie reaping, ordered teardown.
ENTRYPOINT ["/usr/local/bin/rbittorrent-supervisor"]
