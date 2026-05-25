# Production OCI image for yggdrasil.
#
# Two-stage build:
#
#   1. **builder** — installs the rust toolchain + cmake, runs the
#      same CMake/CPack flow used by bare-metal distro packaging,
#      and emits a Debian .deb.
#
#   2. **runtime** — clean `debian:bookworm-slim` that `apt install`s
#      the .deb. The image consumes the same artefact bare-metal
#      operators get, so the install layout is byte-identical between
#      bare-metal, containerised, and Kubernetes deployments.
#
# Plain Dockerfile (OCI) syntax — no BuildKit-only directives — so it
# builds cleanly under `podman build` and `docker build` alike.
#
# For e2e testing with python echo backends and bash helpers, see
# `docker/Dockerfile.e2e` instead.

ARG RUST_VERSION=1.95
ARG DEBIAN_RELEASE=bookworm

# ---------------------------------------------------------------- builder
FROM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS builder

# cmake / build-essential needed for the CMake+CPack frontend, dpkg-dev
# for the .deb shlibdeps autodetection, file for CPackDeb's
# CPACK_DEBIAN_PACKAGE_SHLIBDEPS detection (uses `file` to identify ELF
# objects before running dpkg-shlibdeps on them).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        cmake \
        make \
        build-essential \
        dpkg-dev \
        file \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy manifests first for layer caching. Crate Cargo.toml files are
# enumerated explicitly so a single-crate edit doesn't bust the whole
# dependency cache.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ratatoskr/Cargo.toml     crates/ratatoskr/Cargo.toml
COPY crates/yggdrasil/Cargo.toml     crates/yggdrasil/Cargo.toml
COPY crates/yggdrasilctl/Cargo.toml  crates/yggdrasilctl/Cargo.toml
COPY crates/bench-tools/Cargo.toml   crates/bench-tools/Cargo.toml
COPY crates/cli-defs/Cargo.toml      crates/cli-defs/Cargo.toml

# Stub sources for the dep-cache layer. Cargo builds and caches all
# deps against these placeholders; the next stage replaces the
# sources and only the workspace crates need recompiling.
RUN set -eux; \
    for crate in ratatoskr bench-tools cli-defs; do \
        mkdir -p crates/$crate/src; \
        echo "pub fn _stub() {}" > crates/$crate/src/lib.rs; \
    done; \
    for bin in yggdrasil yggdrasilctl; do \
        mkdir -p crates/$bin/src; \
        echo "fn main() {}" > crates/$bin/src/main.rs; \
    done; \
    echo "pub fn _stub() {}" > crates/yggdrasil/src/lib.rs; \
    # Stubs for [[bench]] entries — names match crates/*/Cargo.toml.
    mkdir -p crates/ratatoskr/benches crates/yggdrasil/benches; \
    echo "fn main() {}" > crates/ratatoskr/benches/noise.rs; \
    echo "fn main() {}" > crates/ratatoskr/benches/rule_parse.rs; \
    echo "fn main() {}" > crates/yggdrasil/benches/flow_table.rs; \
    echo "fn main() {}" > crates/yggdrasil/benches/h3_forward.rs

# Warm the cargo dep cache against stubbed sources. Build via cargo
# directly here (not CMake) because we don't have the real CMakeLists.txt
# in the layer yet — installing it with real sources keeps the
# CMake-driven build identical to bare-metal packaging.
RUN cargo build --release --workspace \
        --bin yggdrasil --bin yggdrasilctl --locked

# Now the real sources, including the CMake / CPack frontend.
COPY . .

# Re-touch sources so cargo notices them after the stub-cache layer.
RUN find crates -name '*.rs' -exec touch {} +

# Build via the same CMake/CPack flow distro packagers use.
# CARGO_LOCKED=ON enforces Cargo.lock — keep production reproducible.
RUN set -eux; \
    cmake -B build -S . \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_BUILD_TYPE=Release \
        -DCARGO_LOCKED=ON \
        -Wno-dev; \
    cmake --build build --parallel; \
    cd build; \
    cpack -G DEB; \
    mkdir -p /out; \
    cp yggdrasil_*.deb /out/yggdrasil.deb

# ---------------------------------------------------------------- runtime
FROM debian:${DEBIAN_RELEASE}-slim AS runtime

# Minimal runtime deps:
#   - ca-certificates: ACME / Let's Encrypt issuance via reqwest+rustls.
#   - systemd: provides systemd-sysusers / systemd-tmpfiles binaries
#     the .deb's postinst would call. The package's postinst guards
#     on `[ -d /run/systemd/system ]` so it no-ops inside a non-systemd
#     container — we run sysusers / tmpfiles ourselves below.
#   - tini: reaps zombie processes when yggdrasil receives signals.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        systemd \
        tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/yggdrasil.deb /tmp/yggdrasil.deb

# Install the .deb. `apt-get install ./` resolves runtime deps;
# --no-install-recommends keeps the image lean.
RUN apt-get update \
 && apt-get install -y --no-install-recommends /tmp/yggdrasil.deb \
 && rm /tmp/yggdrasil.deb \
 && rm -rf /var/lib/apt/lists/* \
 && systemd-sysusers /usr/lib/sysusers.d/yggdrasil.conf \
 && systemd-tmpfiles --create /usr/lib/tmpfiles.d/yggdrasil.conf || true

# Containers don't run systemd; create the runtime dir for the
# control socket manually with the right ownership.
RUN mkdir -p /run/yggdrasil \
 && chown yggdrasil:yggdrasil /run/yggdrasil \
 && chmod 0750 /run/yggdrasil

# Drop to the unprivileged service user. Operators who need to bind
# privileged ports inside the container should override at run time
# with --user 0:0 + --cap-add NET_BIND_SERVICE.
USER yggdrasil

# Operators MUST mount /etc/yggdrasil/config.toml (and conf.d/, certs/,
# identity.key) at run time — the package ships only the .example
# config and refuses to start without a real one.
EXPOSE 51820/udp 80/tcp 443/tcp 443/udp

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["yggdrasil", "run"]
