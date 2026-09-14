# Multi-stage build for the off-chain bridge stack. One image carries every
# off-chain binary; each compose service picks which to run.
#
# Finding H4: the image now also builds the INDEXER (marks transfers
# refund-eligible + records cancel/refund state — without it the refund path
# can't run) and the GRAPHQL-API (the product surface the frontend talks to).
# It runs as a non-root user.

FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release \
      -p validator -p keeper -p sig-store -p indexer -p graphql-api -p price-keeper

FROM debian:bookworm-slim
# ca-certificates + libssl3 cover reqwest's TLS stack (HTTPS RPCs / sig-store);
# curl is used by the compose healthchecks; tini reaps zombies + forwards signals.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 curl tini \
 && rm -rf /var/lib/apt/lists/* \
 # Non-root runtime user (finding H4: containers previously ran as root).
 && groupadd --system --gid 10001 bridge \
 && useradd  --system --uid 10001 --gid bridge --home-dir /data --create-home bridge

COPY --from=builder /build/target/release/validator   /usr/local/bin/validator
COPY --from=builder /build/target/release/keeper       /usr/local/bin/keeper
COPY --from=builder /build/target/release/sig-store    /usr/local/bin/sig-store
COPY --from=builder /build/target/release/indexer      /usr/local/bin/indexer
COPY --from=builder /build/target/release/graphql-api  /usr/local/bin/graphql-api
COPY --from=builder /build/target/release/price-keeper /usr/local/bin/price-keeper

ENV RUST_LOG=info
USER bridge
WORKDIR /data
# tini as PID 1 so Ctrl-C / `docker stop` cleanly terminates the Rust service.
ENTRYPOINT ["/usr/bin/tini", "--"]
# Overridden per-service in docker-compose.yml.
CMD ["sig-store"]
