# Syntax = docker/dockerfile:1
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy host-compiled daemon binary
COPY target/release/dzta-revocation-daemon ./dzta-revocation-daemon

RUN chmod +x ./dzta-revocation-daemon

EXPOSE 50051
CMD ["./dzta-revocation-daemon"]