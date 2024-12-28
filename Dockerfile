﻿# Build stage
FROM docker.io/library/rust:slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Deployment
FROM docker.io/library/debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/servidor-autenticacion-dnie /usr/local/bin/servidor-autenticacion-dnie

EXPOSE 443
ENTRYPOINT ["/usr/local/bin/servidor-autenticacion-dnie"]
