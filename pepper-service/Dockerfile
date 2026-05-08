# syntax=docker/dockerfile:1

# --- builder ------------------------------------------------------------------
FROM rust:1.95-slim-bookworm AS builder

# keyless-common::JwkCache pulls reqwest → openssl-sys, which needs
# pkg-config + libssl-dev at build time.
RUN apt-get update \
  && apt-get install -y --no-install-recommends pkg-config libssl-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Compile only the pepper-service binary from the workspace. We copy the
# whole workspace (not just pepper-service/) because Cargo needs the
# workspace root Cargo.toml + the sibling crates declared in
# `workspace.members` to resolve paths and produce a consistent Cargo.lock.
COPY Cargo.toml Cargo.lock ./
COPY keyless-common ./keyless-common
COPY pepper-service ./pepper-service
COPY poseidon-circomlib ./poseidon-circomlib
COPY prover ./prover
COPY rust-rapidsnark ./rust-rapidsnark

RUN cargo build --release -p movement-keyless-pepper-service

# --- runtime ------------------------------------------------------------------
FROM debian:bookworm-slim

# curl is only here so the HEALTHCHECK line below has something to call.
# Drop it if you wire up healthchecks via a different mechanism.
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

# Non-root user for the service.
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin pepper \
  && mkdir -p /app \
  && chown pepper:pepper /app

WORKDIR /app
COPY --from=builder /build/target/release/movement-keyless-pepper-service /usr/local/bin/pepper-service

USER pepper

# Config — override at `docker run` time:
#
#   PEPPER_ADDR     bind address. Default 0.0.0.0:3002.
#   PEPPER_SECRET   HMAC key used to derive peppers from (sub, aud).
#                   REQUIRED in production — without it the service falls
#                   back to a hardcoded POC default and logs a warning.
#                   Inject via a secrets manager (docker secret, k8s
#                   secret, HSM-fronted sidecar, ...), NEVER bake it into
#                   the image.
ENV PEPPER_ADDR=0.0.0.0:3002

EXPOSE 3002

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3002/health || exit 1

ENTRYPOINT ["/usr/local/bin/pepper-service"]
