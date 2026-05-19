# Multi-stage build that produces a single small runtime image containing
# yggdrasil and yggdrasilctl. compose.e2e.yml picks the right binary per
# service via `command:` overrides.
#
# Plain Dockerfile (OCI) syntax — no BuildKit-only directives — so the build
# runs cleanly under `podman build` (and `docker build` if you ever need it).

ARG RUST_VERSION=1.85
ARG DEBIAN_RELEASE=bookworm

# ---------------------------------------------------------------- builder
FROM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS builder

# Pinned versions live in Cargo.lock; nothing to install beyond what the
# slim image already has (gcc, libc-dev). pkg-config + libssl would be
# needed if we used the rustls/native-tls features — we don't.
WORKDIR /src

# Copy manifests first for layer caching. crate Cargo.toml files are
# enumerated explicitly so a single-crate edit doesn't bust the whole
# dependency cache.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ratatoskr/Cargo.toml       crates/ratatoskr/Cargo.toml
COPY crates/yggdrasil/Cargo.toml       crates/yggdrasil/Cargo.toml
COPY crates/yggdrasilctl/Cargo.toml    crates/yggdrasilctl/Cargo.toml
COPY crates/loadgen/Cargo.toml         crates/loadgen/Cargo.toml

# Stub sources for the dep-cache layer. cargo builds and caches all deps
# against these placeholders; the next stage replaces the sources and
# only the workspace crates need recompiling.
#
# Crates declaring `[[bench]]` (harness=false) also need a stub bench
# source file or cargo refuses to parse the manifest.
RUN set -eux; \
    for crate in ratatoskr loadgen; do \
        mkdir -p crates/$crate/src; \
        echo "pub fn _stub() {}" > crates/$crate/src/lib.rs; \
    done; \
    for bin in yggdrasil yggdrasilctl; do \
        mkdir -p crates/$bin/src; \
        echo "fn main() {}" > crates/$bin/src/main.rs; \
    done; \
    # `yggdrasil` crate is bin+lib, give it a stub lib too.
    echo "pub fn _stub() {}" > crates/yggdrasil/src/lib.rs; \
    # Stubs for [[bench]] entries — names match crates/*/Cargo.toml.
    mkdir -p crates/ratatoskr/benches crates/yggdrasil/benches; \
    echo "fn main() {}" > crates/ratatoskr/benches/noise.rs; \
    echo "fn main() {}" > crates/ratatoskr/benches/rule_parse.rs; \
    echo "fn main() {}" > crates/yggdrasil/benches/flow_table.rs

RUN cargo build --release --workspace \
        --bin yggdrasil --bin yggdrasilctl

# Now real sources.
COPY crates/ crates/

# Touch the entrypoints so cargo notices the new sources after the stub layer.
RUN find crates -name '*.rs' -exec touch {} +

RUN set -eux; \
    cargo build --release --workspace \
        --bin yggdrasil --bin yggdrasilctl; \
    mkdir -p /out; \
    cp target/release/yggdrasil    /out/yggdrasil; \
    cp target/release/yggdrasilctl /out/yggdrasilctl

# ---------------------------------------------------------------- runtime
FROM debian:${DEBIAN_RELEASE}-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        openssl \
        python3 \
        tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/yggdrasil    /usr/local/bin/yggdrasil
COPY --from=builder /out/yggdrasilctl /usr/local/bin/yggdrasilctl

# Helper scripts for the compose e2e topology.
COPY docker/bootstrap.sh       /usr/local/bin/bootstrap.sh
COPY docker/home-entrypoint.sh /usr/local/bin/home-entrypoint.sh
COPY docker/echo-server.py     /usr/local/bin/echo-server.py
RUN chmod 0755 /usr/local/bin/bootstrap.sh \
               /usr/local/bin/home-entrypoint.sh \
               /usr/local/bin/echo-server.py

# Create runtime directories. The compose file mounts volumes over the
# *contents* of these so each container has its own isolated state.
RUN mkdir -p /etc/yggdrasil/rules /etc/yggdrasil/certs \
             /var/lib/yggdrasil /run/yggdrasil \
 && chmod 0750 /run/yggdrasil /etc/yggdrasil/certs

# tini reaps zombies cleanly when sidecar processes (e.g. the python echo
# backend in the `home` service) get killed.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["yggdrasil", "--help"]
