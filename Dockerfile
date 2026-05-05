FROM rust:1.92-slim AS builder

WORKDIR /src

# 1. Copy manifests only and build a dummy binary to cache all dependencies.
#    This layer is only re-run when Cargo.toml or Cargo.lock changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs && cargo build --release && rm -rf src

# 2. Now copy real source and do the actual build.
#    Cargo skips re-compiling dependencies because the cache layer is intact.
COPY src ./src
RUN touch src/main.rs && cargo build --release

# --- Runtime image ---
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables ca-certificates && \
    groupadd --system detrudr && \
    useradd --system --gid detrudr --home-dir /nonexistent --shell /usr/sbin/nologin detrudr && \
    mkdir -p /var/log/detrudr && \
    chown -R detrudr:detrudr /app /var/log/detrudr && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/detrudr /usr/local/bin/detrudr
COPY --chown=detrudr:detrudr config.yaml /app/config.yaml

EXPOSE 8090

USER detrudr

CMD ["detrudr", "--config", "/app/config.yaml"]
