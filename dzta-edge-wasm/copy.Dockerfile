# Syntax = docker/dockerfile:1
FROM envoyproxy/envoy:v1.30.1

WORKDIR /etc/envoy

# Copy host-compiled WASM binary and Envoy config from dzta-edge-wasm directory
COPY target/wasm32-wasip1/release/dzta_edge_wasm.wasm ./dzta_edge_wasm.wasm
COPY dzta-edge-wasm/envoy.yaml ./envoy.yaml

EXPOSE 10000 9901
CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]