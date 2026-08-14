# Syntax = docker/dockerfile:1
# ==============================================================================
# Stage 1: Pure Rust WASM Builder
# ==============================================================================
FROM rustlang/rust:nightly-slim AS builder

# Add WASM target
RUN rustup target add wasm32-wasip1

WORKDIR /usr/src/app

# 1. Copy ONLY the WASM crate source
COPY dzta-edge-wasm ./dzta-edge-wasm

# 2. Dynamically overwrite Cargo.toml to list ONLY dzta-edge-wasm as workspace member
RUN printf '[workspace]\nmembers = ["dzta-edge-wasm"]\nresolver = "2"\n' > Cargo.toml

# 3. Compile WASM binary (NO wasm-opt to avoid ABI corruption)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/app/target \
    cargo build --package dzta-edge-wasm --target wasm32-wasip1 --release --lib && \
    mkdir -p /out && \
    cp target/wasm32-wasip1/release/dzta_edge_wasm.wasm /out/dzta_edge_wasm.wasm

# ==============================================================================
# Stage 2: Envoy Runtime
# ==============================================================================
FROM envoyproxy/envoy:v1.30.1

WORKDIR /etc/envoy

COPY --from=builder /out/dzta_edge_wasm.wasm ./dzta_edge_wasm.wasm
COPY dzta-edge-wasm/envoy.yaml ./envoy.yaml
COPY dzta-edge-wasm/keys ./keys

EXPOSE 10000 9901
CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]