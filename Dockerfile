# Multi-stage Dockerfile for process_triage (pt)
#
# Build: docker build -t pt .
# Run:   docker run --rm --pid=host pt scan
#
# The --pid=host flag is required so pt can see host processes.

# Stage 1: Build static musl binary
FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build release binary with speed optimizations
RUN cargo build --release --bin pt-core \
    --target x86_64-unknown-linux-musl \
    -p pt-core 2>/dev/null \
    || cargo build --release --bin pt-core -p pt-core

# Stage 2: Minimal runtime image
FROM alpine:3.21

RUN apk add --no-cache procps

COPY --from=builder /build/target/release/pt-core /usr/local/bin/pt-core
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/pt-core /usr/local/bin/pt-core 2>/dev/null || true
COPY pt /usr/local/bin/pt

RUN chmod +x /usr/local/bin/pt /usr/local/bin/pt-core

# Non-root user for safety (can still read /proc with --pid=host)
RUN adduser -D -h /home/pt pt
USER pt
WORKDIR /home/pt

ENTRYPOINT ["pt-core"]
CMD ["--help"]
