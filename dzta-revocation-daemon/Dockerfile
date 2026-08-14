# Syntax = docker/dockerfile:1
# ==============================================================================
# Stage 1: Native Builder (Pinned to Debian 12 / Bookworm)
# ==============================================================================
FROM rustlang/rust:nightly-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    clang \
    llvm \
    lld \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# 1. Copy ONLY the daemon crate and its local dependency fabric-client
COPY fabric-client ./fabric-client
COPY dzta-revocation-daemon ./dzta-revocation-daemon

# 2. Dynamically overwrite Cargo.toml to list ONLY these two members
RUN printf '[workspace]\nmembers = ["dzta-revocation-daemon", "fabric-client"]\nresolver = "2"\n' > Cargo.toml

# 3. Compile daemon release binary
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/app/target \
    cargo build --package dzta-revocation-daemon --release && \
    mkdir -p /out && \
    cp target/release/dzta-revocation-daemon /out/

# ==============================================================================
# Stage 2: Daemon Runtime
# ==============================================================================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/dzta-revocation-daemon ./dzta-revocation-daemon

COPY dzta-edge-wasm/config ./config
COPY dzta-edge-wasm/keys ./keys
COPY dzta-edge-wasm/.env ./.env

RUN chmod +x ./dzta-revocation-daemon

EXPOSE 50051
CMD ["./dzta-revocation-daemon"]