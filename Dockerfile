# Multi-stage build for the off-chain bridge stack. One image carries every
# off-chain binary; each compose service picks which to run.
#
# Finding H4: the image now also builds the INDEXER (marks transfers
# refund-eligible + records cancel/refund state — without it the refund path
# can't run) and the GRAPHQL-API (the product surface the frontend talks to).
# It runs as a non-root user.
#
# Every base image is pinned by DIGEST (the tag stays for readability): a tag is
# mutable, so `rust:1-bookworm` could build different code tomorrow with nothing
# in the diff (audit round 5, LOW). Bump by re-resolving the digest:
#   docker buildx imagetools inspect rust:1-bookworm --format '{{json .Manifest.Digest}}'
# CI (static job) refuses an unpinned FROM/image line.

FROM rust:1-bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa AS builder
WORKDIR /build
COPY . .
RUN cargo build --release \
      -p validator -p keeper -p sig-store -p indexer -p graphql-api -p price-keeper

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
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
