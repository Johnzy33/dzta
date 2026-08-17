# Syntax = docker/dockerfile:1
# ==============================================================================
# Stage 1: Workspace Builder
# ==============================================================================
FROM rustlang/rust:nightly-slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    clang \
    llvm \
    lld \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-wasip1

WORKDIR /usr/src/app

# Copy root workspace files
COPY Cargo.toml Cargo.lock* ./

# Copy all workspace crates
COPY src ./src
COPY zkp-core-crypto ./zkp-core-crypto
COPY dzta-edge-wasm ./dzta-edge-wasm
COPY dzta-revocation-daemon ./dzta-revocation-daemon
COPY dzta-protected-prover ./dzta-protected-prover
COPY tee-runner-enclave ./tee-runner-enclave
COPY toxic-waste ./toxic-waste

# BUILD 1: WASM Plugin (Pure WebAssembly / WASI)
RUN cargo build --package dzta-edge-wasm --target wasm32-wasip1 --release --lib

# BUILD 2: Revocation Daemon (Native Binary)
RUN cargo build --package dzta-revocation-daemon --release


# ==============================================================================
# Stage 2a: Enforcer Container (Envoy Proxy + Wasm Plugin)
# ==============================================================================
FROM envoyproxy/envoy:v1.30.1 AS enforcer

COPY --from=builder /usr/src/app/target/wasm32-wasip1/release/dzta_edge_wasm.wasm /etc/envoy/dzta_edge_wasm.wasm
COPY dzta-edge-wasm/envoy.yaml /etc/envoy/envoy.yaml

EXPOSE 10000 9901
CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]


# ==============================================================================
# Stage 2b: Revocation Daemon Container (Native Rust Service)
# ==============================================================================
FROM debian:bookworm-slim AS daemon

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy native binary from the builder stage
COPY --from=builder /usr/src/app/target/release/dzta-revocation-daemon /app/dzta-revocation-daemon

CMD ["/app/dzta-revocation-daemon"]