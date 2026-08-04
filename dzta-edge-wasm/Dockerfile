# Stage 1: Build Rust Wasm Module
FROM rust:1.78-slim as builder

RUN rustup target add wasm32-wasip1

WORKDIR /usr/src/dzta-edge
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY keys ./keys

RUN cargo build --target wasm32-wasip1 --release

# Stage 2: Final MEC Ingress Image
FROM envoyproxy/envoy:v1.30.1

COPY --from=builder /usr/src/dzta-edge/target/wasm32-wasip1/release/dzta_edge_wasm.wasm /etc/envoy/dzta_edge_wasm.wasm
COPY envoy.yaml /etc/envoy/envoy.yaml

EXPOSE 10000 9901

CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]