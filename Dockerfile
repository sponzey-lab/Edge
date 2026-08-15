FROM rust:1.94.0-bookworm AS builder

WORKDIR /workspace
COPY . .
RUN cargo build --release -p edge-proxy

FROM debian:bookworm-slim

RUN useradd --system --home /var/lib/sponzey-edge --create-home edge
WORKDIR /var/lib/sponzey-edge
RUN install -d -o edge -g edge /var/lib/sponzey-edge/data
COPY --from=builder /workspace/target/release/edge-proxy /usr/local/bin/edge-proxy
COPY examples/minimal.toml /etc/sponzey-edge/current.toml
COPY apps/admin-web /usr/share/sponzey-edge/admin-web

ENV SPONZEY_DATA_DIR=/var/lib/sponzey-edge/data
ENV SPONZEY_CONFIG_FILE=/etc/sponzey-edge/current.toml
ENV SPONZEY_ADMIN_BIND=127.0.0.1:9443
ENV SPONZEY_LOG_MODE=product

USER edge
EXPOSE 8080
CMD ["edge-proxy"]
