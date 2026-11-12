# Multi-stage build: compile the AuraChain Quantum v1.0 sovereign node into a ~30 MB image.
#   docker build -t aurachain-quantum .
#   docker run -p 7001:7001 -v aura-data:/data aurachain-quantum \
#       node --port 7001 --data /data --peer https://aurachain-quantum.vercel.app
#   docker run -p 7001:7001 -v aura-data:/data -e AURA_KEY=<64-hex-quantum-seed> \
#       aurachain-quantum node --port 7001 --data /data --key-env AURA_KEY --peer https://aurachain-quantum.vercel.app
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 aura && mkdir /data && chown aura /data
COPY --from=build /src/target/release/aurachain /usr/local/bin/aurachain
USER aura
EXPOSE 7001
VOLUME /data
ENTRYPOINT ["aurachain"]
CMD ["node", "--port", "7001", "--data", "/data", "--peer", "https://aurachain-quantum.vercel.app"]
