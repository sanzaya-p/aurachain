# Multi-stage build: compile the node, ship a ~30 MB runtime image.
#   docker build -t aurachain .
#   docker run -p 7001:7001 -v aura-data:/data aurachain                 # full node (no key)
#   docker run -p 7001:7001 -v aura-data:/data -e AURA_KEY=<secret-hex> \
#       aurachain node --port 7001 --data /data --key-env AURA_KEY --host <public-ip>
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd -r -u 10001 aura && mkdir /data && chown aura /data
COPY --from=build /src/target/release/aurachain /usr/local/bin/aurachain
USER aura
EXPOSE 7001
VOLUME /data
ENTRYPOINT ["aurachain"]
CMD ["node", "--port", "7001", "--data", "/data"]
