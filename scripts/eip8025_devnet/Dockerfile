# The image design 0012's devnet recipe runs: Grandine with SP1 verification
# of EIP-8025 execution proofs, and the execution proof publisher.
#
# Build from the repository root:
#
#     DOCKER_BUILDKIT=1 docker build -f scripts/eip8025_devnet/Dockerfile .
#
# The default Dockerfile is unchanged. Only this image enables
# `execution-proof-sp1`.

# The toolchain follows `rust-toolchain.toml`.
FROM rust:1.95.0-bookworm AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends cmake libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /grandine
COPY . .

# Design 0011's verified command, then the publisher.
RUN cargo build --release -p grandine --features default-networks,execution-proof-sp1 \
    && cargo build --release -p execution_proof_publisher

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder \
    /grandine/target/release/grandine \
    /grandine/target/release/execution_proof_publisher \
    /usr/local/bin/

# ethereum-package runs `sh -c "grandine …"`. The driver runs the publisher
# with `--entrypoint execution_proof_publisher`.
ENTRYPOINT ["grandine"]
