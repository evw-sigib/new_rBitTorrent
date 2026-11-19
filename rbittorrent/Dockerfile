# syntax=docker/dockerfile:1.7
#
# rBittorrent: rtbit + a Rust PID-1 supervisor that owns WireGuard,
# nftables and NAT-PMP. No shell scripts at runtime, no s6, no wg-quick.
#
# Build (CI does this natively per arch, no QEMU):
#   docker buildx build --platform linux/arm64 --build-arg BUILD_ARCH=aarch64 .

ARG ALPINE_VERSION=3.24
ARG RUST_VERSION=1.99

# ---------------------------------------------------------------------------
# rtbit, compiled from the pinned upstream release. The one change to how it
# runs: mimalloc as #[global_allocator] (rtbit/mimalloc.patch). musl's own
# allocator serialises every thread on one lock and holds on to freed
# memory; mimalloc has per-thread heaps and returns pages to the kernel, so
# rtbit's multi-threaded runtime scales over all cores and its RSS drops
# again after a burst (4 GB Raspberry Pis). The tag is cloned shallowly and
# its commit verified, so a moved tag fails the build instead of shipping
# other code. Release profile: opt-level 3, thin LTO, one codegen unit,
# stripped, panic=abort (upstream's own setting).
FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS rtbit
ARG TARGETARCH
ARG RTBIT_REPO=https://github.com/TheDancingDeveloper-org/rustTorrent.git
ARG RTBIT_TAG=v0.2.0-beta.4
ARG RTBIT_COMMIT=be9bbfe5bb406575376a97e827212deff5fe5b8e
# The same build dependencies as upstream's Dockerfile: npm builds the web
# UI (embedded in the binary; `npm ci` against upstream's package-lock.json),
# OpenSSL is linked statically.
RUN apk add --no-cache clang lld git npm pkgconf musl-dev openssl-dev openssl-libs-static
WORKDIR /src
RUN git clone --depth 1 --branch "${RTBIT_TAG}" "${RTBIT_REPO}" . \
 && test "$(git rev-parse HEAD)" = "${RTBIT_COMMIT}"
# auth-banner.patch: the startup log says "auth: enabled" when the login
# the supervisor stored protects the API (upstream printed "not set up").
# swagger-vendored.patch is build-only: Swagger UI (rtbit's /swagger page)
# comes from a checksum-pinned crate instead of a curl download from
# github.com inside build.rs.
# ipv4-fallback.patch: with RTBIT_IPV4_ONLY the DHT and the UDP tracker
# client open 0.0.0.0 instead of [::] (upstream ignored the flag there), and
# without it they fall back to 0.0.0.0 when the kernel has no IPv6
# (ipv6.disable=1 made upstream exit at once).
# completed-move.patch: only torrents still in the download folder are moved
# to the completed folder. Upstream also moved torrents saved elsewhere and,
# on every restart, flattened finished multi-file torrents into it.
# The order matters: auth-banner and swagger-vendored are made on top of
# mimalloc.patch, completed-move on top of ipv4-fallback.
COPY rtbit/mimalloc.patch rtbit/auth-banner.patch rtbit/swagger-vendored.patch \
     rtbit/ipv4-fallback.patch rtbit/completed-move.patch /tmp/
RUN git apply --verbose /tmp/mimalloc.patch /tmp/auth-banner.patch /tmp/swagger-vendored.patch \
      /tmp/ipv4-fallback.patch /tmp/completed-move.patch \
 && grep -q 'static GLOBAL: mimalloc::MiMalloc' crates/rtbit/src/main.rs \
 && grep -q 'store.username()' crates/rtbit/src/main.rs \
 && grep -q '"vendored"' crates/librtbit/Cargo.toml \
 && grep -q 'UDP trackers: cannot open' crates/librtbit-tracker-comms/src/tracker_comms_udp.rs \
 && grep -q 'DHT: cannot open' crates/librtbit-dht/src/dht.rs \
 && grep -q 'new_with_ipv4_only' crates/librtbit/src/session/mod.rs \
 && grep -q 'outside the download folder, not moving it' crates/librtbit/src/session/mod.rs
ENV OPENSSL_STATIC=1 \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=3 \
    CARGO_PROFILE_RELEASE_LTO=thin \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_STRIP=symbols
# --locked: upstream's Cargo.lock plus mimalloc and utoipa-swagger-ui-vendored.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,id=rtbit-${TARGETARCH},sharing=locked \
    cargo build --release --locked -p rtbit \
 && install -D -m 0755 target/release/rtbit /out/rtbit \
 && /out/rtbit --version

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

# Set by CI per architecture. It must match the platform being built, so a
# hand build cannot label an arm64 image as amd64 (checked at build time).
ARG TARGETARCH
ARG BUILD_ARCH
ARG BUILD_VERSION=1.0.0
ARG BUILD_REPOSITORY=evw-sigib/new_rBitTorrent

RUN case "${TARGETARCH}:${BUILD_ARCH}" in \
      amd64:amd64|arm64:aarch64) ;; \
      *) echo "BUILD_ARCH=${BUILD_ARCH:-<unset>} does not match the target platform ${TARGETARCH}"; exit 1 ;; \
    esac
# iproute2-minimal: full netlink `ip` (BusyBox ip cannot create WireGuard
# links). wireguard-tools-wg: only the `wg` binary, no wg-quick.
RUN apk add --no-cache \
      ca-certificates \
      iproute2-minimal \
      nftables \
      wireguard-tools-wg \
      tzdata \
 && rm -rf /var/cache/apk/* /usr/share/man /usr/share/doc

COPY --from=rtbit /out/rtbit /usr/local/bin/rtbit
COPY --from=supervisor /out/rbittorrent-supervisor /usr/local/bin/rbittorrent-supervisor

ENV RUST_BACKTRACE=0

LABEL \
    io.hass.name="rBittorrent" \
    io.hass.description="rtbit behind a fail-closed WireGuard kill-switch with NAT-PMP (or a direct connection)" \
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
