# fabricd — the egress sidecar image.
#
# The workspace path-depends on a sibling checkout of the box repo (../runlet-js) for the
# `fabric-wire` contract crate, so the build CONTEXT IS THE PARENT DIRECTORY holding both
# repos (only sources are copied, never target/):
#
#   git clone https://github.com/hlop3z/runlet-js ../runlet-js   # once
#   docker build -t fabricd -f Dockerfile ..                     # or: task docker-build

# ── Builder (musl static, same toolchain as runlet-js) ────
FROM rust:1.92-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /src
# The contract repo: workspace manifest + member crates (fabric-wire inherits
# version/lints from its own workspace root, so the whole crates/ tree comes along).
COPY runlet-js/Cargo.toml runlet-js/Cargo.toml
COPY runlet-js/crates runlet-js/crates
# This repo.
COPY fabricd/Cargo.toml fabricd/Cargo.lock fabricd/
COPY fabricd/crates fabricd/crates

WORKDIR /src/fabricd
RUN cargo build --release --target x86_64-unknown-linux-musl -p fabricd \
    && strip target/x86_64-unknown-linux-musl/release/fabricd

# ── Runtime (distroless static — no glibc needed) ────────
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /src/fabricd/target/x86_64-unknown-linux-musl/release/fabricd .
COPY fabricd/fabricd.example.json fabricd.example.json

# Mount the real credential table at /app/fabricd.json (see fabricd.example.json).
# UDS transport needs a shared socket volume with the box; the QUIC listener needs
# its configured UDP port published.
ENV FABRICD_CONFIG=/app/fabricd.json

ENTRYPOINT ["./fabricd"]
